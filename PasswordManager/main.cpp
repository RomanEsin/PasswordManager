//
//  main.cpp
//  PasswordManager
//
//  Created by Roman Esin on 05.12.2020.
//

#include <stdio.h>
#include <iostream>
#include <algorithm>
#include <string.h>
#include "SHA256.h"
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <ctime>

#define MASTERFILE "master.txt"

using namespace std;

struct ConfField {
    string domain;
    string login;
    string password;
};

struct Command {
    string command;
    function<void(string)> run;

    Command(const string str, function<void(string)> f) {
        command = str;
        run = f;
    }
};

class PasswordManager {
public:
    // MARK: - Init
    PasswordManager(int count, const char ** values) {
        argc = count;
        argv = values;

        beg = argv;
        end = argv + argc;
    }

    // MARK: - Start
    void start() {
        if (optionExists(beg, end, "help") || optionExists(beg, end, "--help") || optionExists(argv, argv + argc, "-h")) {
            help("");
            return;
        }

        // MARK: - Check config and create fields array.
        setConfig();
        ifstream conf(confPath);

        // Create password if file is empty
        ifstream masterFile(MASTERFILE);

        using placeholders::_1;

        const int commandCount = 5;
        Command availableCommands[] = {
            Command("help", bind(&PasswordManager::help, this, _1)),
            Command("add", bind(&PasswordManager::add, this, _1)),
            Command("get", bind(&PasswordManager::get, this, _1)),
            Command("check", bind(&PasswordManager::check, this, _1)),
            Command("del", bind(&PasswordManager::del, this, _1)),
            Command("master", bind(&PasswordManager::master, this, _1))
        };

        if (isEmpty(conf)) {
            conf.close();

            ofstream confFile(confPath);

            confFile.close();
        }
        
        if (isEmpty(masterFile)) {
            masterFile.close();

            // MARK: - Save new password
            ofstream newConf(MASTERFILE);
            string output = "master:";

            // Generate random seed
            srand((unsigned int)time(NULL));
            int rounds = (rand() % 10) + 5;
//            int rounds = 10;
            newConf << rounds << endl;

            cout << "No password in current config.\n";
            cout << "Please enter a new password\n";
            cout << "Password: ";

            string pass;

            setEchoEnabled(false);
            cin >> pass;
            setEchoEnabled(true);

            enteredPassword = sha256(pass);
            output += enteredPassword;
            string encrypted = encryptDecryptLine(output, rounds, enteredPassword);
            newConf << encrypted;
            newConf.close();
        } else {
            masterFile.close();

            // MARK: - Verify password
            cout << "Password: ";
            string pass;

            setEchoEnabled(false);
            cin >> pass;
            setEchoEnabled(true);
            cout << endl;
            enteredPassword = sha256(pass);
            if (!checkPassword(pass)) {
                cout << "\033[1;31mInvalid password.\033[0m";
                return;
            }
        }

        for (int i = 0; i < commandCount; i++) {
            Command currentCommand = availableCommands[i];
            if (optionExists(beg, end, currentCommand.command)) {
                availableCommands[i].run(currentCommand.command + ' ' + getOption(beg, end, currentCommand.command));
                return;
            }
        }

        cout << "\nWelcome to password manager v1.0!\n";

        string exits[] = {"q", "quit", "exit"};
        string command;
        getline(cin, command);

        // MARK: - Iterpretator
        while (true) {
            cout << ">>> ";

            getline(cin, command);

            if (command == "") {
                continue;
            }

            // Check for exit
            if (isValidFunction(3, exits, command)) {
                cout << "Goodbye!";
                break;
            }

            // Check if function is valid
            if (isValidFunction(6, availableCommands, command)) {
                runCommand(6, availableCommands, command);
            } else {
                cout << "\033[1;31mError: Invalid command.\033[0m\n";
            }
        }

        conf.close();
    }

    // MARK: - Str to field
    ConfField* stringToField(string str) {
        ConfField *field = new ConfField();

        auto pos = str.rfind(':');
        auto space = str.rfind(' ');

        if (pos == string::npos || space == string::npos) {
            return nullptr;
        }

//        cout << str << endl;
//        cout << space << ' ' << pos;

        field->domain = str.substr(0, pos);
        string logStart = str.substr(pos + 1, str.length());
        field->login = logStart.substr(0, logStart.find(' '));
        field->password = str.substr(space + 1, str.length());

//        cout << str << endl;
        
//        cout << field->domain << ' ' << field->login << ' ' << field->password << endl;
        return field;
    }

    // MARK: - Parse line
    ConfField* parseLine(string str) {
        auto space = str.find(' ');
        if (space == string::npos) {
            return nullptr;
        }
        return stringToField(str.substr(space + 1, str.length()));
    }

    // MARK: - Save new field
    void saveFieldToFile(string filePath, int rounds, string line) {
        ofstream file;
        file.open(filePath, ios::app);
        file << rounds << endl;
        file << line << endl;
        file.close();
    }



    // MARK: - Command definitions



    // MARK: - Add
    void add(string command) {
        if (command.find(' ') != string::npos) {
            string strToParse = command.substr(command.find(' ') + 1, command.length());
            ConfField *field = stringToField(strToParse);
            if (field == nullptr) {
                cout << "\033[1;31mError: Invalid arguments passed.\033[0m\n";
                return;
            }

            ifstream inputCheck(confPath);
            ofstream tmp("tmp.txt");
            string line;
            while (getline(inputCheck, line)) {
                int rounds = stoi(line);

                getline(inputCheck, line);
//                encryptDecryptLine(line, rounds, enteredPassword)
                ConfField *inpField = stringToField(encryptDecryptLine(line, rounds, enteredPassword));

                if (inpField == nullptr) {
                    continue;
                }

                if (inpField->domain == field->domain &&
                    inpField->login == field->login) {
                    cout << "Overwriting " << '\'' << field->domain << '\'' << endl;
                    continue;
                }
                tmp << rounds << endl;
                tmp << line << endl;

                delete inpField;
                inpField = nullptr;
            }

            inputCheck.close();
            tmp.close();
            remove(confPath.c_str());
            rename("tmp.txt", confPath.c_str());

            srand((unsigned int)time(NULL));
            int rounds = (rand() % 10) + 5;
//            int rounds = 10;
            string str = encryptDecryptLine(strToParse, rounds, enteredPassword);
            saveFieldToFile(confPath, rounds, str);

            cout << "Saved: " << strToParse << endl;
        } else {
            cout << "\033[1;31mError: Invalid arguments passed.\033[0m\n";
        }
    }

    bool isDigits(const string &str) {
        return str.find_first_not_of("0123456789") == string::npos;
    }

    // MARK: - Get
    void get(string command) {
        if (command.find(' ') != string::npos) {
            string domain = command.substr(command.find(' ') + 1, command.length());
            bool isAll = domain == "all";

            ifstream inputCheck(confPath);
            string line;

            cout << "Finding logins for " << domain << "..." << endl;

            while (getline(inputCheck, line)) {
                // Get how many rounds the line is encoded with
                int rounds = stoi(line);

                string l;
                getline(inputCheck, line);

//                while (!isDigits(line)) {
//
//                    l += line + "\n";
//                }
//                line = l.substr(0, l.length() - 1);

//                encryptDecryptLine(line, rounds, enteredPassword)


                ConfField *inpField = stringToField(encryptDecryptLine(line, rounds, enteredPassword));

                if (inpField == nullptr) {
                    continue;
                }

                if (isAll || inpField->domain == domain) {
//                    cout << encryptDecryptLine(line, rounds, enteredPassword) << endl;
                    if (isAll) {
                        cout << inpField->domain << ": ";
                    }
                    cout << inpField->login << ' ' << inpField->password << endl;
                    continue;
                }

                delete inpField;
                inpField = nullptr;
            }

            inputCheck.close();
        } else {
            cout << "\033[1;31mError: Invalid arguments passed.\033[0m\n";
        }
    }

    // MARK: - Delete
    void check(string command) {
        auto space = command.find(' ');
        auto col = command.rfind(':');

        if (space != string::npos && col != string::npos) {
            string domStart = command.substr(space + 1, command.length());
            string domain = domStart.substr(0, domStart.find(':'));
            string login = command.substr(col + 1, command.length());

            ifstream inputCheck(confPath);
            string line;

            cout << "Finding logins for " << domain << "..." << endl;

            while (getline(inputCheck, line)) {
                // Get how many rounds the line is encoded with
                int rounds = stoi(line);

                string l;
                getline(inputCheck, line);


                ConfField *inpField = stringToField(encryptDecryptLine(line, rounds, enteredPassword));

                if (inpField == nullptr) {
                    continue;
                }

                if (inpField->domain == domain && inpField->login == login) {
                    cout << "There IS a password for " << domain << ":" << login << endl;

                    delete inpField;
                    inpField = nullptr;
                    return;
                }

                delete inpField;
                inpField = nullptr;
            }
            cout << "There is \033[1;31mNO\033[0m password for " << domain << ":" << login << endl;

            inputCheck.close();
        } else {
            cout << "\033[1;31mError: Invalid arguments passed.\033[0m\n";
        }
    }

    void help(string command) {
        string helpString = "Functions:\n\
    help \tShow help message\n\n\
    master \tAlter master password\n\n\
    add \"[domain]:[login] [password]\"\n\
    \t\tCreates a new login:password pair\n\n\
    delete [domain]:[login]\n\
    \t\tDeletes the login and password from the domain\n\
    \t\tDeletes all passwords from the domain\n\n\
    get [domain]:[login]\n\
    \t\tCopies the password to buffer\n\n\
    Options:\n\
    --config, -c\n\
    \t\tSpecify config file path\n\n";
        cout << helpString;
    }

    // MARK: - Delete
    void del(string command) {
        auto space = command.find(' ');
        auto col = command.rfind(':');

        if (space != string::npos && col != string::npos) {
            string domStart = command.substr(space + 1, command.length());
            string domain = domStart.substr(0, domStart.find(':'));
            string login = command.substr(col + 1, command.length());

            ifstream inputCheck(confPath);
            ofstream tmp("tmp.txt");
            string line;

            int deleted = 0;

            while (getline(inputCheck, line)) {
                int rounds = stoi(line);

                getline(inputCheck, line);
                ConfField *inpField = stringToField(encryptDecryptLine(line, rounds, enteredPassword));

                if (inpField == nullptr) {
                    continue;
                }

//                cout << inpField->domain << ' ' << inpField->login << endl;
//                cout << inpField->login.find(login) << endl;

                if (inpField->domain == domain && inpField->login == login) {
                    delete inpField;
                    inpField = nullptr;
                    deleted++;
                    continue;
                }

                tmp << rounds << endl;
                tmp << line << endl;

                delete inpField;
                inpField = nullptr;
            }

            inputCheck.close();
            tmp.close();
            remove(confPath.c_str());
            rename("tmp.txt", confPath.c_str());

            cout << endl;
            if (deleted > 0) {
                cout << "Deleted `" << login << "` from `" << domain << "`!" << endl;
            } else {
                cout << "No such domains found!" << endl;
            }
        } else {
            cout << "\033[1;31mError: Invalid arguments passed.\033[0m\n";
        }
    }

    // MARK: - Master
    void master(string command) {
        cout << "Are you sure, you want to change the master password?\n";
        cout << "[y/n]: ";

        string answer;
        cin >> answer;

        if (answer != "y" && answer != "Y") {
            return;
        }

        cout << "No password in current config.\n";
        cout << "Please enter a new password\n";
        cout << "Password: ";

        string pass;

        setEchoEnabled(false);
        cin >> pass;
        setEchoEnabled(true);

        cout << endl;

        ofstream newConf(MASTERFILE);
        string output = "master:";

        srand((unsigned int)time(NULL));
        int rounds = 10;
        newConf << rounds << endl;

        enteredPassword = sha256(pass);
        output += enteredPassword;
        string encrypted = encryptDecryptLine(output, rounds, enteredPassword);
        newConf << encrypted;
        newConf.close();

        cout << "Saved new password!\n";
    }

    // MARK: - Run commands
    void runCommand(int fCount, Command funcs[fCount], string command) {
        for (int i = 0; i < fCount; i++) {
            if (command.rfind(funcs[i].command) == 0) {
                funcs[i].run(command);
                return;
            }
        }
    }

    bool checkPassword(string pass) {
        pass = sha256(pass);
        return getMasterField(pass).password == pass;
    }

    void showHelp(string command) {
        cout << "Help for " << command << " asdoj asd fasd fdsa fasd f asf d" << endl;
    }

    // MARK: - Set config
    void setConfig() {
        if (optionExists(beg, end, "--config")) {
            confPath = getOption(beg, end, "--config");
            return;
        }

        if (optionExists(beg, end, "-c")) {
            confPath = getOption(beg, end, "-c");
            return;
        }

        confPath = "default.txt";
    }

private:
    const char ** beg;
    const char ** end;

    int argc;
    const char ** argv;
    string confPath;
    string enteredPassword;

    // MARK: - Valid from strings
    bool isValidFunction(int fCount, string funcs[fCount], string command) {
        for (int i = 0; i < fCount; i++) {
            if (command.rfind(funcs[i]) == 0) {
                return true;
            }
        }

        return false;
    }

    // MARK: - Valid from Commands
    bool isValidFunction(int fCount, Command funcs[fCount], string command) {
        for (int i = 0; i < fCount; i++) {
            if (command.rfind(funcs[i].command) == 0) {
                return true;
            }
        }

        return false;
    }

    // MARK: - Line getting methods
    ConfField getMasterField(string password) {
        ConfField field;
        field.domain = "master";

        ifstream conf(MASTERFILE);
        string line;

        getline(conf, line);
        int rounds = stoi(line);
        string full = "";
        while (getline(conf, line)) {
            full += line + "\n";
        }
        full = full.substr(0, full.length() - 1);
        line = encryptDecryptLine(full, rounds, password);
        if (line.rfind("master:", 0) == 0) {
            auto pos = line.find(":");
            field.password = line.substr(pos + 1, line.length());
            conf.close();
            return field;
        }

        conf.close();
        return field;
    }

    // MARK: - Line getting methods
    vector<string> getLinesWhereDomain(string containedStr) {
        vector<string> lines;

        ifstream conf(confPath);
        string line;
        while (getline(conf, line)) {
            if (line.rfind(containedStr, 0) == 0) {
                lines.push_back(line);
            }
        }
        conf.close();
        return lines;
    }

    // MARK: - Is empty
    bool isEmpty(ifstream& pFile) {
        return pFile.peek() == ifstream::traits_type::eof();
    }

    // REFERENCE: https://stackoverflow.com/a/1455007/10616784
    void setEchoEnabled(bool enable) {
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);
        if( !enable )
            tty.c_lflag &= ~ECHO;
        else
            tty.c_lflag |= ECHO;

        (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    }

    // MARK: - Options methods
    const char* getOption(const char ** begin, const char ** end, const string option) {
        const char ** itr = find(begin, end, option);
        if (itr != end && ++itr != end) {
            return *itr;
        }
        return 0;
    }

    bool optionExists(const char** begin, const char** end, const string option) {
        return find(begin, end, option) != end;
    }

    // MARK: - Crypt stuff
    string encryptDecryptLine(string l, int rounds, string key) {
        int keys[64];
        generateKeys(keys, key);

        string end = l;
        // For each round
        for (int i = 0; i < l.length(); i++) {
            // Do 8 rounds
            for (int j = 0; j < rounds; j++) {
                // XOR the letter with the key
                // at `i + j + key[i]` and write that to string
                end[i] = end[i] ^ keys[(i + j + keys[i % 64]) % 64];
            }
        }

        return end;
    }

    // MARK: - Generate keys
    void generateKeys(int keys[64], string key) {
        for (int i = 0; i < 64; i++) {
            int part = (int)key[i];
            keys[i] = part;
        }
    }
};


int main(int argc, const char ** argv) {

    PasswordManager passMan(argc, argv);

    passMan.start();

    cout << endl;

    
    return 0;
}
