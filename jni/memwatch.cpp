/**
 * @brief Self-modification Detection for ARM64 Programs
 *
 * This implementation monitors and controls memory protection changes to detect
 * self-modifying code patterns. It uses seccomp filters to intercept mprotect
 * calls and ptrace to handle memory access violations.
 *
 * The detection works by:
 * 1. Intercepting attempts to make memory both writable and executable
 * 2. Removing write permissions from such memory
 * 3. Catching write attempts through SIGSEGV handling
 * 4. Allowing controlled single-instruction modifications
 */

#include <android/log.h>
#include <arpa/inet.h>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <iomanip>
#include <iostream>
#include <linux/seccomp.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unordered_map>
#include <unordered_set>

#define TAG "MemWatch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))

void print_colored(const char *message, bool is_detected) {
  // ANSI escape codes: Red = \033[31m, Green = \033[32m, Reset = \033[0m
  if (is_detected) {
    std::cout << "\033[31m" << message << "\033[0m" << std::endl;
  } else {
    std::cout << "\033[32m" << message << "\033[0m" << std::endl;
  }
}

class Debugger {
private:
  // Process ID of the target being monitored
  pid_t target_pid;
  bool skip_mode;

  // Set of monitored thread IDs
  std::unordered_set<pid_t> monitored_threads;

  // Mutex for thread set synchronization
  std::mutex threads_mutex;

  // Maps protected page addresses to their sizes
  // Used to track pages where write permission has been removed
  std::unordered_map<uintptr_t, size_t> protected_pages;

  // State tracking for single-step execution
  bool waiting_for_single_step = false;
  uintptr_t page_to_reprotect = 0;
  size_t page_size_to_reprotect = 0;
  std::vector<uint64_t> whitelist_addresses;

  std::map<uint64_t, uint64_t> address_call_counts;

  void increment_address_call_count(uint64_t addr) {
    uint64_t page_addr = addr & PAGE_MASK;
    address_call_counts[page_addr]++;
  }

  uint64_t get_address_call_count(uint64_t addr) {
    uint64_t page_addr = addr & PAGE_MASK;
    auto it = address_call_counts.find(page_addr);
    if (it != address_call_counts.end()) {
      return it->second;
    }
    return 0;
  }

  bool is_address_in_whitelist(uint64_t addr) {

    uint64_t target_page = addr & PAGE_MASK;

    for (uint64_t whitelist_addr : whitelist_addresses) {
      uint64_t whitelist_page = whitelist_addr & PAGE_MASK;
      if (target_page == whitelist_page) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Attach to a single thread
   * @param tid Thread ID to attach to
   * @return true if successfully attached
   */
  bool attach_single_thread(pid_t tid) {
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
      std::cerr << "Failed to attach to thread " << tid << std::endl;
      return false;
    }

    int status;
    waitpid(tid, &status, 0);

    // Set the same options as the main thread
    unsigned long options = PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                            PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK |
                            PTRACE_O_TRACEVFORKDONE;

    if (ptrace(PTRACE_SETOPTIONS, tid, 0, options) == -1) {
      std::cerr << "Failed to set options for thread " << tid << std::endl;
      return false;
    }

    // Continue the thread after attaching
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
      std::cerr << "Failed to continue thread " << tid << std::endl;
      return false;
    }

    return true;
  }

  /**
   * @brief Attach to all existing threads of the target process
   */
  void attach_all_threads() {
    char task_path[32];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", target_pid);

    DIR *dir = opendir(task_path);
    if (!dir) {
      throw std::runtime_error("Failed to open task directory");
    }

    std::lock_guard<std::mutex> lock(threads_mutex);
    while (struct dirent *entry = readdir(dir)) {
      if (entry->d_name[0] == '.')
        continue;

      pid_t tid = std::stoi(entry->d_name);
      if (attach_single_thread(tid)) {
        monitored_threads.insert(tid);
        std::cout << "Attached to thread " << tid << std::endl;
      }
    }
    closedir(dir);
  }

  /**
   * @brief Handle new thread creation event
   * @param parent_tid Thread ID that created the new thread
   */
  void handle_thread_clone(pid_t parent_tid) {
    unsigned long new_tid;
    if (ptrace(PTRACE_GETEVENTMSG, parent_tid, 0, &new_tid) != -1) {
      std::lock_guard<std::mutex> lock(threads_mutex);
      monitored_threads.insert(new_tid);
      std::cout << "New thread " << new_tid << " created by " << parent_tid << std::endl;
    }
  }

  /**
   * @brief Remove thread from monitoring set
   * @param tid Thread ID to remove
   */
  void remove_thread(pid_t tid) {
    std::lock_guard<std::mutex> lock(threads_mutex);
    monitored_threads.erase(tid);
    std::cout << "Thread " << tid << " removed from monitoring" << std::endl;
  }

  /**
   * @brief Execute mprotect syscall in the target process
   *
   * This function performs a remote mprotect call by:
   * 1. Saving the current process state
   * 2. Injecting an SVC instruction
   * 3. Setting up syscall arguments
   * 4. Single-stepping the instruction
   * 5. Restoring the original state
   *
   * Note: Uses 0xDEADBEAF in x3 register to bypass seccomp filters
   *
   * @param addr Address to change protection
   * @param len Length of memory region
   * @param prot New protection flags
   */
  void remote_mprotect(pid_t tid, void *addr, size_t len, int prot) {
    struct user_regs_struct regs, original_regs;
    struct iovec iov;
    unsigned long original_insn;

    // Save current registers
    iov.iov_base = &original_regs;
    iov.iov_len = sizeof(original_regs);
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to get original registers");
    }

    // Save current instruction (8-byte aligned for ARM64)
    original_insn = ptrace(PTRACE_PEEKTEXT, tid, original_regs.pc, nullptr);
    if (original_insn == -1) {
      throw std::runtime_error("Failed to read instruction");
    }

    // Set up registers for mprotect syscall
    regs = original_regs;
    regs.regs[8] = __NR_mprotect;                     // x8: syscall number
    regs.regs[0] = reinterpret_cast<uintptr_t>(addr); // x0: address
    regs.regs[1] = len;                               // x1: length
    regs.regs[2] = prot;                              // x2: protection flags
    regs.regs[3] = 0xDEADBEAF;                        // x3: special flag for seccomp bypass

    // Update registers in target process
    iov.iov_base = &regs;
    if (ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to set registers");
    }

    // Write SVC instruction (0xD4000001) while preserving upper 4 bytes
    unsigned long svc_insn = (original_insn & 0xFFFFFFFF00000000ULL) | 0xD4000001;
    if (ptrace(PTRACE_POKETEXT, tid, original_regs.pc, svc_insn) == -1) {
      throw std::runtime_error("Failed to write SVC instruction");
    }

    // Execute SVC instruction
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1) {
      throw std::runtime_error("Failed to single step");
    }

    int status;
    waitpid(tid, &status, 0);
    if (!WIFSTOPPED(status)) {
      std::cerr << "Process not stopped: status = " << std::hex << status << std::endl;
      throw std::runtime_error("Process not stopped after single step");
    }

    // Get syscall result
    struct user_regs_struct result_regs;
    iov.iov_base = &result_regs;
    iov.iov_len = sizeof(result_regs);
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to get registers after syscall");
    }

    // Check result (x0 contains return value)
    long result = result_regs.regs[0];
    if (result < 0) {
      std::cerr << "mprotect failed with error: " << -result << std::endl;
    }

    // Restore original instruction
    if (ptrace(PTRACE_POKETEXT, tid, original_regs.pc, original_insn) == -1) {
      throw std::runtime_error("Failed to restore original instruction");
    }

    // Restore registers
    iov.iov_base = &original_regs;
    if (ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to restore registers");
    }
  }

  /**
   * @brief Handle seccomp events for mprotect calls
   * @param tid Thread ID that triggered the event
   *
   * Intercepts mprotect system calls and enforces W^X policy by:
   * 1. Removing write permission if both write and execute are requested
   * 2. Recording protected pages for later SIGSEGV handling
   *
   * When a page is requested to be both writable and executable,
   * this handler removes the write permission and logs the page
   * for monitoring write attempts.
   */
  void handle_seccomp_event(pid_t tid) {
    unsigned long msg;
    if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &msg) == -1) {
      throw std::runtime_error("Failed to get seccomp event message");
    }

    struct user_regs_struct regs;
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to get registers");
    }

    void *addr = reinterpret_cast<void *>(regs.regs[0]);
    size_t len = regs.regs[1];
    int prot = regs.regs[2];

    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
      if (is_address_in_whitelist(reinterpret_cast<uint64_t>(addr))) {
        increment_address_call_count(reinterpret_cast<uint64_t>(addr));
        if (get_address_call_count(reinterpret_cast<uint64_t>(addr)) <= 2) {
          LOGI("Allowing WX permission for whitelisted address: %p", addr);
          return;
        }
      }
      LOGI("Disallowing WX permission for non-whitelisted address: %p", addr);

      int new_prot = prot & ~PROT_WRITE | PROT_READ;
      regs.regs[2] = new_prot;
      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);

      if (ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
        throw std::runtime_error("Failed to set registers");
      }

      protected_pages[reinterpret_cast<uintptr_t>(addr)] = len;

      std::cout << "Modified protection for thread " << tid << "\n"
                << "New protection: 0x" << std::hex << new_prot << std::dec << "\n";
    }
  }

  /**
   * @brief Handle SIGSEGV signals from write attempts to protected pages
   * @param tid Thread ID that received SIGSEGV
   *
   * When a write is attempted to a protected page:
   * 1. Temporarily enables write permission
   * 2. Single-steps the instruction
   * 3. Immediately restores protection
   *
   * This allows controlled single-instruction modifications while
   * maintaining overall write protection.
   */
  void handle_sigsegv(pid_t tid) {
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) == -1) {
      throw std::runtime_error("Failed to get signal info");
    }

    void *fault_addr = si.si_addr;

    // Get registers at time of fault
    struct user_regs_struct regs;
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
      throw std::runtime_error("Failed to get registers");
    }

    char buf[256];
    snprintf(buf, sizeof(buf),
             "  Fault Address: %p\n"
             "  Instruction Address: %p\n"
             "  Access Type: %s\n",
             fault_addr, (void *)regs.pc, si.si_code == SEGV_ACCERR ? "Permission Error" : "Invalid Address");
    print_colored("Memory Access Exception", true);
    std::cout << buf << std::endl;

    uintptr_t fault_addr_int = reinterpret_cast<uintptr_t>(fault_addr);
    for (const auto &[base_addr, length] : protected_pages) {
      if (fault_addr_int >= base_addr && fault_addr_int < base_addr + length) {
        std::cout << "Protected page access detected" << std::endl;

        if (skip_mode) {
          print_colored("Skipping Memory Access Instruction", false);
          struct user_regs_struct regs;
          struct iovec iov;
          iov.iov_base = &regs;
          iov.iov_len = sizeof(regs);

          if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
            throw std::runtime_error("Failed to get registers");
          }

          regs.pc += 4;

          if (ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov) == -1) {
            throw std::runtime_error("Failed to set registers");
          }
        } else {
          remote_mprotect(tid, reinterpret_cast<void *>(base_addr), length, PROT_READ | PROT_WRITE | PROT_EXEC);

          if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1) {
            throw std::runtime_error("Failed to set single step");
          }

          int status;
          waitpid(tid, &status, 0);

          remote_mprotect(tid, reinterpret_cast<void *>(base_addr), length, PROT_READ | PROT_EXEC);
        }

        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
    }

    std::cout << "Unprotected page access, propagating signal" << std::endl;
    ptrace(PTRACE_CONT, tid, nullptr, si.si_signo);
  }

public:
  /**
   * @brief Constructor
   * @param pid Target process ID to monitor
   */
  Debugger(pid_t pid, bool skip_mode, std::vector<uint64_t> whitelist_addresses)
      : target_pid(pid), skip_mode(skip_mode), whitelist_addresses(whitelist_addresses) {}

  /**
   * @brief Attach to target process and set up ptrace options
   *
   * Establishes ptrace connection and enables:
   * - Seccomp event tracking (for mprotect interception)
   * - Syscall tracking
   */
  void attach() {
    attach_all_threads();
    std::cout << "Successfully attached to process " << target_pid << " and all its threads" << std::endl;
  }

  /**
   * @brief Main event loop
   *
   * Monitors and handles:
   * - Seccomp events (mprotect calls)
   * - SIGSEGV signals (write attempts)
   * - Process exit
   */
  void run() {
    while (true) {
      int status;
      pid_t tid = waitpid(-1, &status, __WALL);
      if (tid == -1) {
        if (errno == ECHILD) {
          std::cout << "No more threads to monitor\n";
          break;
        }
        continue;
      }

      if (WIFSTOPPED(status)) {
        int stopsig = WSTOPSIG(status);
        if (stopsig == SIGSTOP) {
          siginfo_t si;
          if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) == 0) {
            if (si.si_signo == SIGCHLD && si.si_addr == nullptr) {
              std::cout << "Thread " << tid << " stopped due to thread creation" << std::endl;

              unsigned long options = PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE |
                                      PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK |
                                      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE;

              if (ptrace(PTRACE_SETOPTIONS, tid, 0, options) == -1) {
                std::cerr << "Failed to set options for thread " << tid << ": " << strerror(errno) << std::endl;
              }
            }
          }
          ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        } else if (stopsig == SIGTRAP) {
          unsigned int event = status >> 16;
          if (event == PTRACE_EVENT_CLONE) {
            handle_thread_clone(tid);
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
          } else if (event == PTRACE_EVENT_SECCOMP) {
            handle_seccomp_event(tid);
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
          } else if ((status & 0xffff) == (SIGTRAP | 0x80)) {
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
          }
        } else if (stopsig == SIGSEGV) {
          handle_sigsegv(tid);
        }
      } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
        remove_thread(tid);
        if (tid == target_pid) {
          std::cout << "Main thread exited\n";
          break;
        }
      }
    }
  }
};

/**
 * @brief Main entry point
 *
 * Usage: program <pid>
 * Attaches to the specified process and monitors for self-modification attempts
 */
int main(int argc, char *argv[]) {
  int server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock < 0) {
    LOGE("socket error");
    return 1;
  }
  int opt = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    LOGE("setsockopt error");
    close(server_sock);
    return 1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(12345);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOGE("bind error");
    close(server_sock);
    return 1;
  }

  if (listen(server_sock, 1) < 0) {
    LOGE("listen error");
    close(server_sock);
    return 1;
  }

  LOGI("Server listening on port 12345...");

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
  if (client_sock < 0) {
    LOGE("accept error");
    close(server_sock);
    return 1;
  }

  LOGI("Client connected from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

  uint32_t pid;
  if (recv(client_sock, &pid, sizeof(pid), 0) != sizeof(pid)) {
    LOGE("recv error: %s", strerror(errno));
    close(client_sock);
    close(server_sock);
    return 1;
  }

  LOGI("Received PID: %u", pid);

  uint32_t whitelist_count;
  if (recv(client_sock, &whitelist_count, sizeof(whitelist_count), 0) != sizeof(whitelist_count)) {
    LOGE("recv error: %s", strerror(errno));
    close(client_sock);
    close(server_sock);
    return 1;
  }
  LOGI("Receiving %u whitelist addresses", whitelist_count);

  std::vector<uint64_t> whitelist_addresses;
  for (uint32_t i = 0; i < whitelist_count; i++) {
    uint64_t address;
    if (recv(client_sock, &address, sizeof(address), 0) != sizeof(address)) {
      LOGE("recv error: %s", strerror(errno));
      close(client_sock);
      close(server_sock);
      return 1;
    }
    whitelist_addresses.push_back(address);
    LOGI("Received whitelist address: 0x%lx", address);
  }

  close(client_sock);
  close(server_sock);

  bool skip_mode = false;

  if (argc < 1 || argc > 2) {
    std::cerr << "Usage: " << argv[0] << " [-s]\n";
    return 1;
  }

  // Check for the optional '-s' flag
  if (argc == 2 && std::string(argv[1]) == "-s") {
    skip_mode = true;
  }

  pid_t target_pid = pid;

  try {
    Debugger dbg(target_pid, skip_mode, whitelist_addresses);
    dbg.attach();
    dbg.run();
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}