#include <iostream>
#include <vector>
#include <stack>
#include <queue>
#include <string>
#include <regex>
#include <filesystem>
#include <system_error>
#include <map>
#include <set>
#include <optional>
#include <list>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/wait.h>
#include <signal.h>

namespace fs = std::filesystem;

enum class ShellStringType
{
    kNone,
    kString,
    kStringWithBackslash,
    kCommand,
    kShellVar,
    kPathSpecial,
    kEnvOrVar,
    kVarDefinition,
    kSpace,
    kAsterisk,
    kRegex,
    kInvalidDollar
};

enum class CommandType
{
    kInvalid = 0x0,
    kAmpersand = 0x1,
    kPipe = 0x2,
    kSemicolon = 0x3,
    kRightAngleBracket = 0x4,
    kLeftAngleBracket = 0x5,
    kDoubleAmpersand = (kAmpersand << 4) | kAmpersand,
    kDoubleVerticalBar = (kPipe << 4) | kPipe,
    kRightDoubleAngleBracket = (kRightAngleBracket << 4) | kRightAngleBracket,
    kLeftDoubleAngleBracket = (kLeftAngleBracket << 4) | kLeftAngleBracket,
};

bool CheckValidity(const std::string& __k_line) noexcept;
std::vector< std::pair<std::string, ShellStringType> > LineParsing(std::string &__line, std::error_code& __ec) noexcept;
CommandType CommandStringToComandType(const std::string& __k_multiple_command_string, std::error_code& __ec) noexcept;
std::string StringToRegex(const std::string& __k_string) noexcept;
std::string RegexToString(const std::string& __k_regex_string) noexcept;
std::vector<std::string> GetFileListByRegexString(std::string __regex_string, std::error_code& __ec) noexcept;
bool IsMultipleCommandType(const CommandType& __k_command) noexcept;
bool IsRedirectionCommandType(const CommandType& __k_command) noexcept;
void Cd(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void Export(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void Echo(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void VarDefinition(const std::string& __arg, std::error_code& __ec) noexcept;
void Unset(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void Redirection(CommandType __redirection_type, const std::pair<std::string, ShellStringType>& __k_entry, std::error_code& __ec);
void History(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void ShellExit(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept;
void BashError(const std::string& __error_msg);
void GlobalInit();
pid_t ExecCommand(const std::vector<std::string>& __k_args_by_string, std::error_code& __ec, bool force_builtin_fork = false);
void SigintHandler(int);

std::map<std::string, std::string> g_var_value_map;
std::set<std::string> g_no_value_env_set;
extern char **environ;
const static std::regex g_k_defienition_regex(R"(_=|(?:(^[a-zA-Z\_]\w*)=))", std::regex::optimize);
const static std::regex g_k_env_name_check_regex(R"(^_$|(^[a-zA-Z\_]\w*$))", std::regex::optimize);
pid_t g_sigint_pid = 0;
bool g_end_flag = false;
std::deque<std::string> g_command_history_deque;
const std::map<std::string, void (*)(const std::vector<std::string>&, std::error_code&)> g_k_builtin_fuction_map = 
{
    {"cd", Cd},
    {"export", Export},
    {"echo", Echo},
    {"unset", Unset},
    {"history", History},
    {"exit", ShellExit}
};

int main(int argc, char** argv, char** envp)
{
    std::list<std::pair<pid_t, std::string>> background_process_list;
    int stdin_fd_bakup = dup(STDIN_FILENO);;
    int stdout_fd_backup = dup(STDOUT_FILENO);
    int stderr_fd_backup = dup(STDERR_FILENO);
    GlobalInit();

    do
    {
        std::string line = "";
        std::vector< std::pair<std::string, ShellStringType> > parsed_line_vec;
        std::queue<std::string> var_definition_queue;
        std::error_code error_code;
        CommandType redirection_type = CommandType::kInvalid;
        struct passwd *pw;
        pw = getpwuid(getuid());
        char hostname[257] = { '\0' };
        gethostname(hostname, 257);
        if (fs::current_path().compare(pw->pw_dir) == 0)
        {
            std::cout << pw->pw_name << "@" << hostname << ":" << fs::path("~").string() << "$ " << std::flush;
        }
        else if(fs::current_path().compare(pw->pw_dir) > 0)
        {
            std::cout << pw->pw_name << "@" << hostname << ":" << (fs::path("~") / fs::current_path().lexically_relative(pw->pw_dir)).string() << "$ " << std::flush;
        }
        else
        {
            std::cout << pw->pw_name << "@" << hostname << ":" << fs::current_path().string() << "$ " << std::flush;
        }

        std::getline(std::cin, line);

        while(CheckValidity(line) == false)
        {
            std::string pre_line;

            std::cout << "> ";

            std::getline(std::cin, pre_line);
            line += pre_line;
        }

        if(getenv("HISTSIZE") != nullptr)
        {
            std::string history_size = getenv("HISTSIZE");
            if(all_of(history_size.begin(), history_size.end(), ::isdigit) == false)
            {
                std::error_code tmp_ec;
                Export({"HISTSIZE=1000"}, tmp_ec);
            }
        }
        else
        {
            std::error_code tmp_ec;
            Export({"HISTSIZE=1000"}, tmp_ec);
        }

        size_t history_size = std::atoi(getenv("HISTSIZE"));

        if(!line.empty())
        {
            while(g_command_history_deque.empty() == false && g_command_history_deque.size() >= history_size)
                g_command_history_deque.pop_front();

            if(history_size) g_command_history_deque.push_back(line);
        }

        while(!line.empty())
        {
            parsed_line_vec = LineParsing(line, error_code);
            if(error_code) continue;

            std::vector<std::string> args_by_string;
            bool redirection_clear_flag = false;
            g_end_flag = false;

            if(parsed_line_vec.empty() == false && parsed_line_vec.back().second != ShellStringType::kCommand)
            {
                parsed_line_vec.push_back({";", ShellStringType::kCommand});
            }

            for (std::pair<std::string, ShellStringType> parsed_entry : parsed_line_vec)
            {

                if(error_code)
                {
                    std::error_code tmp_error_code;

                    if(parsed_entry.second != ShellStringType::kCommand || IsMultipleCommandType(CommandStringToComandType(parsed_entry.first, tmp_error_code)) == false)
                    {
                        continue;
                    }
                }
                if(parsed_entry.second == ShellStringType::kVarDefinition && (args_by_string.empty() == false || redirection_type != CommandType::kInvalid))
                {
                    parsed_entry.second = ShellStringType::kString;
                }
                if (redirection_type != CommandType::kInvalid)
                {
                    Redirection(redirection_type, parsed_entry, error_code);
                    if(error_code) break;
                    redirection_type = CommandType::kInvalid;
                    redirection_clear_flag = true;
                    continue;
                }
                

                switch (parsed_entry.second)
                {
                case ShellStringType::kString:
                    args_by_string.push_back(parsed_entry.first);
                    break;
                case ShellStringType::kVarDefinition:
                    if(args_by_string.empty()) var_definition_queue.push(parsed_entry.first);
                    else                       assert(false);
                    break;
                case ShellStringType::kRegex:
                {
                    std::vector<std::string> file_list = GetFileListByRegexString(parsed_entry.first, error_code);
                    args_by_string.insert(args_by_string.end(), file_list.begin(), file_list.end());
                    break;
                }
                case ShellStringType::kCommand:
                {
                    CommandType command_type = CommandStringToComandType(parsed_entry.first, error_code);
                
                    if(IsMultipleCommandType(command_type))
                    {
                        error_code.clear();

                        if(args_by_string.empty() == false) 
                        {
                            std::queue<std::string> tmp_queue;
                            var_definition_queue.swap(tmp_queue);
                            pid_t child_pid;
                            int child_status;

                            switch (command_type)
                            {
                            case CommandType::kAmpersand:
                                child_pid = ExecCommand(args_by_string, error_code, true);
                                g_sigint_pid = child_pid;
                                if(child_pid >= 0 && !error_code)
                                {
                                    if(child_pid)
                                    {
                                        std::cout << "[" << (background_process_list.size() + 1) << "] " << child_pid << std::endl;
                                        background_process_list.push_back({child_pid, args_by_string[0]});
                                    }
                                }
                                break;
                            case CommandType::kDoubleAmpersand:
                                child_pid = ExecCommand(args_by_string, error_code);
                                if (child_pid > 0 && !error_code)
                                {
                                    waitpid(child_pid, &child_status, 0);
                                    if(!WIFEXITED(child_status) || WEXITSTATUS(child_status) != EXIT_SUCCESS) g_end_flag = true;
                                }
                                else if (error_code)
                                {
                                    g_end_flag = true;
                                }
                                break;
                            case CommandType::kPipe:
                                child_pid = ExecCommand(args_by_string, error_code);
                                g_sigint_pid = child_pid;
                                if (child_pid > 0)
                                {
                                    waitpid(child_pid, &child_status, 0);
                                    if(WIFEXITED(child_status) &&  WEXITSTATUS(child_status) == EXIT_SUCCESS) g_end_flag = true;
                                }
                                else if (!error_code)
                                {
                                    g_end_flag = true;
                                }
                                break;
                            case CommandType::kDoubleVerticalBar:
                                child_pid = ExecCommand(args_by_string, error_code);
                                g_sigint_pid = child_pid;
                                if (child_pid > 0)
                                {
                                    waitpid(child_pid, &child_status, 0);
                                    if(WIFEXITED(child_status) &&  WEXITSTATUS(child_status) == EXIT_SUCCESS) g_end_flag = true;
                                }
                                else if (!error_code)
                                {
                                    g_end_flag = true;
                                }
                                break;
                            case CommandType::kSemicolon:
                                child_pid = ExecCommand(args_by_string, error_code);
                                g_sigint_pid = child_pid;
                                if (child_pid > 0)
                                {
                                    waitpid(child_pid, &child_status, 0);
                                }
                                break;
                            default:
                                assert(false);
                                break;
                            }

                            args_by_string.clear();
                        }
                        else
                        {
                            if(var_definition_queue.empty())
                            {
                                BashError("syntax errror near unexpedted token `" + parsed_entry.first + "'");
                                g_end_flag = true;
                            }
                            else
                            {
                                while(!var_definition_queue.empty())
                                {
                                    VarDefinition(var_definition_queue.front(), error_code);
                                    var_definition_queue.pop();
                                }
                            }

                        }

                        if(redirection_clear_flag == true)
                        {
                            dup2(stdin_fd_bakup, STDIN_FILENO);
                            dup2(stdout_fd_backup, STDOUT_FILENO);
                            dup2(stderr_fd_backup, STDERR_FILENO);
                            close(stdin_fd_bakup);
                            close(stdout_fd_backup);
                            close(stderr_fd_backup);
                            stdin_fd_bakup = dup(STDIN_FILENO);
                            stdout_fd_backup = dup(STDOUT_FILENO);
                            stderr_fd_backup = dup(STDERR_FILENO);
                            redirection_clear_flag = false;
                        }

                    }
                    else if(IsRedirectionCommandType(command_type))
                    {
                        redirection_type = command_type;
                    }
                    else
                    {
                        assert(false);
                    }

                    break;
                }
                default:
                    std::cerr << static_cast<int>(parsed_entry.second) << std::endl;
                    throw std::runtime_error("예상치 못한 파싱 오류");
                    assert(false);
                    break;
                }

                if(g_end_flag)
                {
                    line.clear();
                    break;
                }
            }

            dup2(stdin_fd_bakup, STDIN_FILENO);
            dup2(stdout_fd_backup, STDOUT_FILENO);
            dup2(stderr_fd_backup, STDERR_FILENO);
            close(stdin_fd_bakup);
            close(stdout_fd_backup);
            close(stderr_fd_backup);
            stdin_fd_bakup = dup(STDIN_FILENO);
            stdout_fd_backup = dup(STDOUT_FILENO);
            stderr_fd_backup = dup(STDERR_FILENO);

            if(redirection_type != CommandType::kInvalid)
            {
                BashError("syntax error near unexpected token `newline'");
            }
        }

        for (auto iter = background_process_list.cbegin(); iter != background_process_list.cend();)
        {
            int child_status;
            auto &[pid, cmd]=*iter;
            int ret;

            if((ret = waitpid(pid, &child_status, WNOHANG)) > 0)
            {
                std::cout << "[" << (background_process_list.size()) << "] " << ((WEXITSTATUS(child_status) == 0)? "DONE" :"Exit " + std::to_string(WEXITSTATUS(child_status))) << "\t\t" + cmd << std::endl;
                iter = background_process_list.erase(iter);
            }
            else if(ret < 0)
            {
                iter = background_process_list.erase(iter);
            }
            else
            {
                iter++;
            }
        }

    } while (true);
}

std::vector< std::pair<std::string, ShellStringType> > LineParsing(std::string &__line, std::error_code& __ec) noexcept
{
    // 6.
    // 파싱 결과는 std::pair<std::string, ShellStringType>의 형태이다.
    // pair.first에는 파싱한 문자열을, pair.second에는 파싱 문자열의 종류를 넣는다.

    // 1st group : (?:\"((?:\\\"|[^\"])*)\")
    // "string" 캡처
    // 2nd group : (?:\'((?:\\\'|[^\'])*)\')
    // 'string' 캡처
    // 3rd group : (?:\$([0-9\*\@\#\$\!]))
    // shell 변수 캡처
    // 4th group : (?:\$(\w+))
    // 환경변수 또는 변수 캡처
    // 5th group : (_=)
    // 잘못된 변수 선언 캡처
    // 6th gruop : (?:([a-zA-Z\_]\w*=))
    // 변수 선언 캡처
    // 7th group : ([0-9]\w+=)
    // 잘못된 변수 선언 캡처
    // 8th group : ([\~][^\/\ \n])
    // 잘못된 경로 특수문자 캡처 (문자열 취급)
    // 9th group : ([\~])
    // 경로 특수문자 캡처
    // 10th group : ((?:[^<>|&;\"\'\$\ \n\\\*]|\\.)+)
    // 기타 공백으로 구분되는 문자열 캡처, \문자 형식 포함
    // 11th group : (?:(\*)+)
    // *(asterisk) 캡처
    // 12th group : ([<>|&]{2})
    // 쉘 멀티 커맨드 문자 (연속) 캡처
    // 13th group : ([<>|&;]{1})
    // 쉘 멀티 커맨드 문자 캡처
    // 14th group : (?:( ) *)
    // 공백 캡처
    // 15th group : (\$)
    // 잘못된 $문자 캡처
    // const static std::regex k_line_regex(R"((?:\"((?:\\\"|[^\"])*)\")|(?:\'((?:\\\'|[^\'])*)\')|(?:\$(\w+))|(\w+=)|((?:[^<>|&;\"\'\$\ \n\\\*]|\\.)+)|(?:(\*)+)|([<>|&]{2})|([<>|&;]{1})|(?:( ) *)|([\$]+))", std::regex::optimize);
    const static std::regex k_line_regex(R"((?:\"((?:\\\"|[^\"])*)\")|(?:\'((?:\\\'|[^\'])*)\')|(?:\$([0-9\*\@\#\$\!]))|(?:\$(\w+))|(_=)|(?:([a-zA-Z\_]\w*=))|([0-9]\w+=)|([\~][^\/\ \n])|([\~])|((?:[^<>|&;\"\'\$\ \n\\\*]|\\.)+)|(?:(\*)+)|([<>|&]{2})|([<>|&;]{1})|(?:( ) *)|(\$)|(\\))", std::regex::optimize);
    constexpr std::array<ShellStringType, 16> k_is_special_caputre_block = 
    {
        ShellStringType::kString, 
        ShellStringType::kString, 
        ShellStringType::kString, 
        ShellStringType::kShellVar,
        ShellStringType::kEnvOrVar,
        ShellStringType::kString,
        ShellStringType::kVarDefinition,
        ShellStringType::kString,
        ShellStringType::kString,
        ShellStringType::kPathSpecial,
        ShellStringType::kStringWithBackslash, 
        ShellStringType::kAsterisk,
        ShellStringType::kCommand, 
        ShellStringType::kCommand, 
        ShellStringType::kSpace,
        ShellStringType::kString
    };
    std::smatch line_match;
    std::vector<std::pair<std::string, ShellStringType>> parsed_line_entry_vec; // first : 파싱된 문자열, second : 쉘 명령어 문자 (예 : &&) 해당 여부
    std::vector<std::pair<std::string, ShellStringType>> tmp_parsed_line_entry_vec;

    while(std::regex_search(__line, line_match, k_line_regex))
    {
        bool parsing_stop_flag = false;
        for (size_t i = 1; i < line_match.size(); i++)
        {
            const std::string k_parsed_string = line_match[i];

            if(k_parsed_string.empty() == false)
            {
                parsed_line_entry_vec.push_back({std::move(k_parsed_string), k_is_special_caputre_block[i]});
                if(k_is_special_caputre_block[i] == ShellStringType::kCommand)
                {
                    CommandType command_type = CommandStringToComandType(parsed_line_entry_vec.back().first, __ec);
                    if(__ec.value() != 0) { BashError(std::string("syntax error near unexpected token `") + parsed_line_entry_vec.back().first.back() + '\''), __line.clear(); return {}; }
                    if(IsMultipleCommandType(command_type))
                    {
                        parsing_stop_flag = true;
                    }
                }
                break;
            }
        }

        __line = line_match.suffix();

        if(parsing_stop_flag) break;
    }

    // *$"asdf"나 $"HOSTTYPE"과 같은 경우를 위해, kInvalidDollor 뒤에 공백이 아닌 문자열이 오면 kInvalidDollor을 제거한다.
    for (std::pair<std::string, ShellStringType>& parsed_line_entry : parsed_line_entry_vec)
    {
        if (tmp_parsed_line_entry_vec.empty() == false && tmp_parsed_line_entry_vec.back().second == ShellStringType::kInvalidDollar)
        {
            switch (parsed_line_entry.second)
            {
            case ShellStringType::kString:
            case ShellStringType::kStringWithBackslash:
                tmp_parsed_line_entry_vec.pop_back();
            }
        }

        tmp_parsed_line_entry_vec.push_back(parsed_line_entry);
    }

    parsed_line_entry_vec = std::move(tmp_parsed_line_entry_vec);
    tmp_parsed_line_entry_vec.clear();

    // 공백 문자열 (" ")을 제거한다.
    // 파싱 과정에서 분리된 문자열(예: ./"this is"/"test dir"는 ./, "this is", / "this dir"로 파싱된다.)을
    // 다시 이어 붙인다.
    // // \(문자)를 (문자)로 변환한다.
    const static std::regex k_remove_backslash_regex(R"(\\(.))", std::regex::optimize);
    const static std::regex k_find_asterisk_regex(R"((\*))", std::regex::optimize);
    bool new_string_flag = true;
    struct passwd *pw = getpwuid(getuid());
    for (std::pair<std::string, ShellStringType>& parsed_line_entry : parsed_line_entry_vec)
    {
        switch (parsed_line_entry.second)
        {
        case ShellStringType::kEnvOrVar:
            if (g_var_value_map[parsed_line_entry.first] != "") parsed_line_entry.first = g_var_value_map[parsed_line_entry.first];
            else if(getenv(parsed_line_entry.first.c_str()))    parsed_line_entry.first = std::string(getenv(parsed_line_entry.first.c_str()));
            else                                                continue;
            parsed_line_entry.second = ShellStringType::kString;
            if(parsed_line_entry.first.find('*') != std::string::npos)
            {
                    parsed_line_entry.first = std::regex_replace(parsed_line_entry.first, k_find_asterisk_regex, R"(.*)");
                    parsed_line_entry.second = ShellStringType::kRegex;
                    break;
            }
            break;
        case ShellStringType::kStringWithBackslash:
            parsed_line_entry.first = std::regex_replace(parsed_line_entry.first, k_remove_backslash_regex, "$1");
            parsed_line_entry.second = ShellStringType::kString;
            break;
        case ShellStringType::kAsterisk:
            parsed_line_entry.first = ".*";
            parsed_line_entry.second = ShellStringType::kRegex;
            break;
        case ShellStringType::kVarDefinition:
            if (std::isdigit(parsed_line_entry.first.front())) parsed_line_entry.second = ShellStringType::kString;
            break;
        case ShellStringType::kInvalidDollar:
            parsed_line_entry.second = ShellStringType::kString;
            break;
        case ShellStringType::kPathSpecial:
            if(parsed_line_entry.first == "~") parsed_line_entry.first = pw->pw_dir? pw->pw_dir : "";
            parsed_line_entry.second = ShellStringType::kString;
            break;
        case ShellStringType::kShellVar: // 임시처리
            continue;
            break;
        case ShellStringType::kCommand:
            CommandStringToComandType(parsed_line_entry.first, __ec);
            if(__ec.value() != 0) { BashError(std::string("syntax error near unexpected token `") + parsed_line_entry.first.back() + '\'');  return {}; }
            tmp_parsed_line_entry_vec.push_back(std::move(parsed_line_entry));
            new_string_flag = true;
            continue;
        case ShellStringType::kSpace:
            new_string_flag = true;
            continue;
        case ShellStringType::kNone:
            continue;
        }

        if (new_string_flag == true)
        {
            tmp_parsed_line_entry_vec.push_back(std::move(parsed_line_entry));
            new_string_flag = false;
        }
        else
        {
            switch (parsed_line_entry.second)
            {
            case ShellStringType::kString:
                switch (tmp_parsed_line_entry_vec.back().second)
                {
                case ShellStringType::kString:
                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kVarDefinition:
                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kRegex:
                    parsed_line_entry.first = StringToRegex(parsed_line_entry.first);
                    parsed_line_entry.second = ShellStringType::kRegex;

                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                }
                break;
            case ShellStringType::kRegex:
                switch (tmp_parsed_line_entry_vec.back().second)
                {
                case ShellStringType::kString:
                    tmp_parsed_line_entry_vec.back().first = StringToRegex(tmp_parsed_line_entry_vec.back().first);
                    tmp_parsed_line_entry_vec.back().second = ShellStringType::kRegex;

                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kVarDefinition:
                    parsed_line_entry.first = RegexToString(parsed_line_entry.first);
                    parsed_line_entry.second = ShellStringType::kString;

                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kRegex:
                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                }
                break;
            case ShellStringType::kVarDefinition:
                switch (tmp_parsed_line_entry_vec.back().second)
                {
                case ShellStringType::kString:
                    parsed_line_entry.second = ShellStringType::kString;
                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kVarDefinition:
                    parsed_line_entry.second = ShellStringType::kString;
                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                    break;
                case ShellStringType::kRegex:
                    tmp_parsed_line_entry_vec.back().first = RegexToString(tmp_parsed_line_entry_vec.back().first);
                    tmp_parsed_line_entry_vec.back().second = ShellStringType::kString;
                    parsed_line_entry.second = ShellStringType::kString;

                    tmp_parsed_line_entry_vec.back().first += parsed_line_entry.first;
                }
                break;
            }
        }
    }

    // parsed_line_entry_vec = std::move(tmp_parsed_line_entry_vec);
    // tmp_parsed_line_entry_vec.clear();

    // \(문자)를 (문자)로 변환한다.
    // for (std::pair<std::string, ShellStringType>& parsed_line_entry : parsed_line_entry_vec)
    // {
    //     const static std::regex parsed_line_regex("\\\\(.)", std::regex::optimize);
    //     parsed_line_entry.first = std::regex_replace(parsed_line_entry.first, parsed_line_regex, "$1");
    // }

    return tmp_parsed_line_entry_vec;
}

std::string StringToRegex(const std::string& __k_string) noexcept
{
    const static std::regex k_add_backslash_regex(R"(([^a-zA-Z0-9\/]))", std::regex::optimize);
    return std::regex_replace(__k_string, k_add_backslash_regex, R"(\$1)");
}

std::string RegexToString(const std::string& __k_regex_string) noexcept
{
    std::string normal_string;

    const static std::regex k_wildcard_regex_to_asterisk_regex(R"((\.\*))", std::regex::optimize);
    const static std::regex k_remove_backslash_regex(R"(\\([^a-zA-Z0-9\/]))", std::regex::optimize);

    normal_string = std::regex_replace(__k_regex_string, k_wildcard_regex_to_asterisk_regex, R"(*)");
    normal_string = std::regex_replace(normal_string, k_remove_backslash_regex, R"($1)");

    return normal_string;
}

bool CheckValidity(const std::string& __k_line) noexcept
{
    char ch = '\0';
    bool multiple_command = false;
    bool have_normal_string = false;

    for (size_t i = 0; i < __k_line.size(); i++)
    {
        if ((ch == '\'' || ch == '\"') && __k_line[i] == ch)
        {
            ch = '\0';
            have_normal_string = true;
        }
        else
        {
            switch (__k_line[i])
            {
            case '\\':
                i++;
                multiple_command = false;
                break;
            case '\'':
            case '\"':
                ch = __k_line[i];
                multiple_command = false;
                break;
            case '&':
            case '|':
                if(__k_line[i] != '&' || (i + 1 < __k_line.size() && __k_line[i + 1] == '&'))
                {
                    multiple_command = true;
                }
                break;
            case ' ':
            case '>':
            case '<':
                break;
            default:
                multiple_command = false;
                have_normal_string = true;
            }
        }
    }

    return !(ch || multiple_command);
}

void GlobalInit()
{
    std::error_code init_ec;
    
    setsid();
    signal(SIGINT, SigintHandler);

    Export({"PWD=" + fs::current_path(init_ec).string()}, init_ec);
    if(init_ec) BashError("GlobalInit: set PWD: " + init_ec.message() + ", exit(EXIT_FAILURE)"), exit(EXIT_FAILURE);

    Export({"HISTSIZE=" + std::to_string(1000)}, init_ec);
    if(init_ec) BashError("GlobalInit: set PWD: " + init_ec.message() + ", exit(EXIT_FAILURE)"), exit(EXIT_FAILURE);
}

std::vector<std::string> GetFileListByRegexString(std::string __regex_string, std::error_code& __ec) noexcept
{
    std::string backup_regex_string;
    std::smatch regex_string_match;
    std::string now_regex_string = "";
    const static std::regex k_parsing_regex(R"((\/?[^\/\n]+))", std::regex::optimize);
    std::queue<fs::path> path_queue;
    std::vector<std::string> matched_vector;
    bool relative_flag = false;

    __ec.clear();

    if(__regex_string.front() == '/')
    {
        path_queue.push("/");
    }
    else
    {
        path_queue.push(fs::current_path());
        now_regex_string = fs::current_path();
        relative_flag = true;
    }

    while(std::regex_search(__regex_string, regex_string_match, k_parsing_regex))
    {
        const std::string k_parsed_string = regex_string_match[1];

        const size_t k_path_queue_size = path_queue.size();

        now_regex_string += k_parsed_string;
        std::regex path_regex(now_regex_string);

        for (size_t i = 0; i < k_path_queue_size; i++)
        {
            fs::path k_to_search_path = path_queue.front();
            path_queue.pop();

            if (fs::is_directory(k_to_search_path))
            {
                for (const fs::directory_entry& k_entry : fs::directory_iterator(k_to_search_path, __ec))
                {
                    if(std::regex_match(k_entry.path().string(), path_regex))
                        path_queue.push(k_entry.path());
                }
            }

        }

        __regex_string = regex_string_match.suffix();
    }

    while (!path_queue.empty())
    {
        if(relative_flag == true)
        {
            matched_vector.push_back(path_queue.front().lexically_relative(fs::current_path()));
        }
        else
        {
            matched_vector.push_back(path_queue.front().string());
        }
        path_queue.pop();
    }

    std::sort(
        matched_vector.begin(), 
        matched_vector.end(), 
        [](const std::string& __k_x, const std::string& __k_y)->bool{ return strcasecmp(__k_x.c_str(), __k_y.c_str()) < 0; }
    );

    if(matched_vector.empty()) return {RegexToString(backup_regex_string)};
    else                       return matched_vector;
}

CommandType CommandStringToComandType(const std::string& __k_multiple_command_string, std::error_code& __ec) noexcept
{
    __ec.clear();
    
    if(__k_multiple_command_string.empty() || __k_multiple_command_string.size() > 2)
    {
        __ec = std::make_error_code(std::errc::invalid_argument);
        return CommandType::kInvalid;
    }

    if(__k_multiple_command_string.front() != __k_multiple_command_string.back()) // 앞과 뒤가 다르다 == "&|" 과 같은 문자열이다.
    {
        __ec = std::make_error_code(std::errc::invalid_argument);
        return CommandType::kInvalid;
    }

    int enum_integer_var = 0x0;

    switch (__k_multiple_command_string.front())
    {
    case '<':
        enum_integer_var = static_cast<int>(CommandType::kLeftAngleBracket);
        break;
    case '>':
        enum_integer_var = static_cast<int>(CommandType::kRightAngleBracket);
        break;
    case '&':
        enum_integer_var = static_cast<int>(CommandType::kAmpersand);
        break;
    case '|':
        enum_integer_var = static_cast<int>(CommandType::kPipe);
        break;
    case ';':
        enum_integer_var = static_cast<int>(CommandType::kSemicolon);
        break;
    default:
        __ec = std::make_error_code(std::errc::invalid_argument);
        return CommandType::kInvalid;
        break;
    }

    if(__k_multiple_command_string.size() == 2)
    {
        enum_integer_var = (enum_integer_var << 4) | enum_integer_var;

        if(enum_integer_var == static_cast<int>(CommandType::kLeftDoubleAngleBracket))
        {
            __ec = std::make_error_code(std::errc::invalid_argument);
            return CommandType::kInvalid;
        }
    }

    return static_cast<CommandType>(enum_integer_var);
}

bool IsMultipleCommandType(const CommandType& k_command) noexcept
{
    const static std::set<CommandType> k_multiple_command_set = { CommandType::kAmpersand, CommandType::kPipe, CommandType::kSemicolon, CommandType::kDoubleAmpersand, CommandType::kDoubleVerticalBar };

    return k_multiple_command_set.count(k_command);
}

bool IsRedirectionCommandType(const CommandType& k_command) noexcept
{
    const static std::set<CommandType> k_multiple_command_set = { CommandType::kLeftAngleBracket, CommandType::kRightAngleBracket, CommandType::kLeftDoubleAngleBracket, CommandType::kRightDoubleAngleBracket };

    return k_multiple_command_set.count(k_command);
}

void Cd(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    struct passwd *pw = getpwuid(getuid());
    __ec.clear();

    switch (__k_args.size())
    {
    case 0:
        if(pw->pw_dir != nullptr)
        {
            fs::current_path(pw->pw_dir, __ec);
            if(getenv("PWD") != nullptr)
            {
                setenv("OLDPWD", getenv("PWD"), true);
                setenv("PWD", fs::current_path().string().c_str(), true);
            }
        }
        else
        {
            __ec = std::make_error_code(std::errc::no_such_file_or_directory);
        }
        
        break;
    case 1:
        fs::current_path(__k_args[0], __ec);

        if(__ec)
        {
            BashError("cd: " + __k_args[0] + ": " + __ec.message());
        }
        else
        {
            if(getenv("PWD") != nullptr)
            {
                setenv("OLDPWD", getenv("PWD"), true);
                setenv("PWD", fs::current_path().string().c_str(), true);
            }
        }

        break;
    default:
        BashError("cd: too many arguments");
        __ec = std::make_error_code(std::errc::argument_list_too_long);
        break;
    }
}

void Export(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    __ec.clear();

    if (__k_args.empty())
    {
        std::vector<std::string> shell_env_vec;

        for (size_t i = 0; environ[i]; i++)
        {
            shell_env_vec.push_back(environ[i]);
        }

        for (const std::string& k_env_name: g_no_value_env_set)
        {
            shell_env_vec.push_back(k_env_name);
        }

        std::sort(shell_env_vec.begin(), shell_env_vec.end());

        for (const std::string& k_env : shell_env_vec)
        {
            std::cout << "declare -x " << k_env << std::endl;
        }
    }
    else if((__k_args[0].size() == 1)? __k_args[0][0] == '_' : __k_args[0].compare(0, 2, "_=") == 0)
    {
        return;
    }
    else
    {
        std::smatch arg_match;

        try
        {
            for (std::string arg : __k_args)
            {
                bool have_value_flag = false;

                if(arg.find('=', 0) != std::string::npos) have_value_flag = true;

                if (arg == "_") continue;

                if(have_value_flag)
                {
                    std::regex_search(arg, arg_match, g_k_defienition_regex);

                    const std::string k_env_name = arg_match[1];
                    arg = arg_match.suffix();

                    if(k_env_name.empty() == false)
                    {
                        setenv(k_env_name.c_str(), arg.c_str(), true);
                        g_var_value_map[std::move(k_env_name)] = std::move(arg);
                    }
                    else
                    {
                        BashError("`" + arg + "' : not a valid identifier");
                        __ec = std::make_error_code(std::errc::invalid_argument);
                    }
                }
                else
                {
                    if(std::regex_match(arg, arg_match, g_k_env_name_check_regex))
                    {
                        if(g_var_value_map.find(arg) != g_var_value_map.end())
                        {
                            setenv(arg.c_str(), g_var_value_map[arg].c_str(), false);
                        }
                        else
                        {
                            g_no_value_env_set.insert(std::move(arg));
                        }
                    }
                    else
                    {
                        BashError("`" + arg + "' : not a valid identifier");
                        __ec = std::make_error_code(std::errc::invalid_argument);
                    }
                }
            }
        }
        catch(std::exception e)
        {
            std::cout << e.what() << std::endl;
        }
    }
}

void Echo(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    __ec.clear();

    for (const std::string& k_arg : __k_args)
    {
        std::cout << k_arg << ' ';
    }

    std::cout << std::endl;
}

void VarDefinition(const std::string& __arg, std::error_code& __ec) noexcept
{
    __ec.clear();

    size_t equal_sign_location = __arg.find('=');
    std::string value;

    assert(equal_sign_location != std::string::npos);

    const std::string k_env_name = __arg.substr(0, equal_sign_location);

    if(equal_sign_location != std::string::npos) value = __arg.substr(equal_sign_location + 1);
    else                                         value = "";

    try
    {
        if (g_no_value_env_set.count(k_env_name))
        {
            g_no_value_env_set.erase(k_env_name);
            setenv(k_env_name.c_str(), value.c_str(), true);
        }
        else if(getenv(k_env_name.c_str()) != nullptr)
        {
            setenv(k_env_name.c_str(), value.c_str(), true);
        }
    }
    catch(std::exception e)
    {
        std::cout << e.what() << std::endl;
    }
    
    g_var_value_map[std::move(k_env_name)] = std::move(value);
}

void Unset(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    std::smatch arg_match;
    __ec.clear();

    for (const std::string& k_arg : __k_args)
    {
        if(k_arg == "_") continue;
        
        if(std::regex_match(k_arg, arg_match, g_k_env_name_check_regex))
        {
            g_no_value_env_set.erase(k_arg);
            g_var_value_map.erase(k_arg);
            if(getenv(k_arg.c_str()) != nullptr)
            {
                unsetenv(k_arg.c_str());
            }
        }
        else
        {
            BashError("`" + k_arg + "' : not a valid identifier");
            __ec = std::make_error_code(std::errc::invalid_argument);
        }
    }
}

void History(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    if(__k_args.empty() == false)
    {
        __ec = std::make_error_code(std::errc::argument_list_too_long);
        BashError("export: argument list too long");
    }
    else
    {
        size_t i = 1;

        for (const std::string& line : g_command_history_deque)
        {
            std::cout.width(5);
            std::cout << i << "  " << line << std:: endl;
            i++;
        }
    }
}

void ShellExit(const std::vector<std::string>& __k_args, std::error_code& __ec) noexcept
{
    if(__k_args.empty())
    {
        exit(0);
    }
    else
    {
        std::string exit_code_string = __k_args[0];
        int8_t exit_code_int;

        try
        {
            exit_code_int = std::stoi(exit_code_string);
        }
        catch(const std::exception& e)
        {
            __ec = std::make_error_code(std::errc::invalid_argument);
            BashError("exit: " + exit_code_string + ": numeric argument required");
            exit(2);
        }
        
        
        if((__k_args.size() > 1))
        {
            __ec = std::make_error_code(std::errc::argument_list_too_long);
            BashError("exit: too many arguments");
            exit(EXIT_FAILURE);
        }
        else
        {
            exit(exit_code_int);
        }
    }
}

void BashError(const std::string& __error_msg)
{
    std::cerr << "bash: " << __error_msg << std::endl;
}

void Redirection(CommandType __redirection_type, const std::pair<std::string, ShellStringType>& __k_entry, std::error_code& __ec)
{
    __ec.clear();

    auto error_func = [&]()->void
    {
        BashError(__k_entry.first + ": " + strerror(errno));
        __ec = std::error_code(errno, std::generic_category());
        errno = 0;
    };

    if(__k_entry.second == ShellStringType::kRegex)
    {
        BashError(RegexToString(__k_entry.first) + ": ambiguous redirect");
        __ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }
    else if(__k_entry.second != ShellStringType::kString)
    {
        BashError("syntax error near unexpected token `" + __k_entry.first.back() + '\'');
        __ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    int file_fd;
    int ret;

    switch (__redirection_type)
    {
    case CommandType::kLeftAngleBracket:
        if(access(__k_entry.first.c_str(), R_OK) == -1)
        {
            BashError(__k_entry.first + ": " + strerror(errno));
            __ec = std::error_code(errno, std::generic_category());
            errno = 0;
            break;
        }
        file_fd = open(__k_entry.first.c_str(), O_RDONLY);
        ret = dup2(file_fd, STDIN_FILENO);
        close(file_fd);
        break;
    case CommandType::kRightAngleBracket:
        file_fd = open(__k_entry.first.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if(file_fd == -1) {error_func(); break;}
        ret = dup2(file_fd, STDOUT_FILENO);
        close(file_fd);
        break;
    case CommandType::kRightDoubleAngleBracket:
        file_fd = open(__k_entry.first.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
        if(file_fd == -1) {error_func(); break;}
        ret = dup2(file_fd, STDOUT_FILENO);
        close(file_fd);
        break;
    default:
        throw std::runtime_error("invalid redirection type");
        break;
    }
}

char** StringVectorToCstringArray(const std::vector<std::string>& __vec)
{
    char** cstring_array = new char*[__vec.size() + 1];

    for (size_t i = 0; i < __vec.size(); i++)
    {
        cstring_array[i] = strdup(__vec[i].c_str());
    }
    cstring_array[__vec.size()] = nullptr;

    return cstring_array;
}

void DeleteCstringArray(char** cstring_array)
{
    for (size_t i = 0; cstring_array[i]; i++)
    {
        free(cstring_array[i]);
    }
    delete[] cstring_array;
}

pid_t ExecCommand(const std::vector<std::string>& __k_args_by_string, std::error_code& __ec, bool force_builtin_fork)
{
    __ec.clear();

    auto error_func = [&]()->pid_t
    {
        BashError(__k_args_by_string[0] + ": " + strerror(errno));
        __ec = std::error_code(errno, std::generic_category());
        errno = 0;
        return -1;
    };

    auto error_is_a_directory_func = [&]()->pid_t
    {
        BashError(__k_args_by_string[0] + ": " + "Is a directory");
        __ec = std::make_error_code(std::errc::is_a_directory);
        return -1;
    };

    if(__k_args_by_string.empty())
    {
        throw std::runtime_error("empty args");
    }
    
    if (g_k_builtin_fuction_map.find(__k_args_by_string[0]) != g_k_builtin_fuction_map.end())
    {
        auto buitin_function = g_k_builtin_fuction_map.find(__k_args_by_string[0])->second;

        if (force_builtin_fork == false)
        {
            buitin_function(std::vector<std::string>(__k_args_by_string.begin() + 1, __k_args_by_string.end()), __ec);
            return 0;
        }
        else
        {
            pid_t rc = fork();

            if (rc < 0)
            {
                return error_func();
            }
            else if (rc == 0)
            {
                buitin_function(std::vector<std::string>(__k_args_by_string.begin() + 1, __k_args_by_string.end()), __ec);
                if(__ec) 
                {
                    BashError(__k_args_by_string[0] + ": " + __ec.message());
                    exit(EXIT_FAILURE);
                }
                else
                {
                    exit(EXIT_SUCCESS);
                }
            }
            else
            {
                return rc;
            }
        }
    }
    else if(__k_args_by_string[0] == "exit")
    {
        if (force_builtin_fork == false)
        {
            exit(0);
            return 0;
        }
        else
        {
            pid_t rc = fork();

            if (rc < 0)
            {
                return error_func();
            }
            else if (rc == 0)
            {
                exit(0);
            }
            else
            {
                return rc;
            }
        }
    }
    else if(__k_args_by_string[0].find('/') != std::string::npos)
    {
        if (__ec) return error_func();

        if(!access(__k_args_by_string[0].c_str(), X_OK))
        {
            if(fs::is_directory(__k_args_by_string[0], __ec))
            {
                error_is_a_directory_func();
                return -1;
            }
            else if(__ec)
            {
                errno = __ec.value();
                error_func();
                return -1;
            }

            char** args = StringVectorToCstringArray(__k_args_by_string);
            pid_t rc = fork();

            if (rc < 0)
            {
                return error_func();
            }
            else if (rc == 0)
            {
                execv(args[0], args);
                DeleteCstringArray(args);
                error_func();
                exit(EXIT_FAILURE);
            }
            else
            {
                DeleteCstringArray(args);
                return rc;
            }
        }
        else
        {
            return error_func();
        }
    }
    else
    {
        if (__ec) return error_func();

        char** args = StringVectorToCstringArray(__k_args_by_string);
        pid_t rc = fork();

        if (rc < 0)
        {
            return error_func();
        }
        else if (rc == 0)
        {
            execvp(args[0], args);
            DeleteCstringArray(args);
            error_func();
            exit(EXIT_FAILURE);
        }
        else
        {
            DeleteCstringArray(args);
            return rc;
        }
    }

    return -1;
}

void SigintHandler(int)
{
    if(g_sigint_pid > 0)
    {
        kill(g_sigint_pid, SIGINT);
        g_sigint_pid = 0;
    }
}