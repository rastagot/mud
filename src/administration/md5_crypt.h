#ifndef MD5_CRYPT_H_
#define MD5_CRYPT_H_

#include <string>

namespace Password {

// Тот же результат, что у glibc crypt() для соли "$1$": ASCII-строка
// "$1$<соль>$<хэш>". Соль — либо "$1$....$", либо уже записанный хэш.
std::string md5_crypt(const std::string &password, const std::string &salt);

} // namespace Password

#endif // MD5_CRYPT_H_
