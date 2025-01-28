import sys
import socket
import threading

# Yazdırılabilir karakterleri tanımlayan filtre
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)]
)

def hexdump(src, length=16, show=True):
    # Eğer veri byte türündeyse, string'e dönüştür
    if isinstance(src, bytes):
        src = src.decode()

    results = []

    # Veriyi 'length' uzunluğunda parçalara ayırarak işleme
    for i in range(0, len(src), length):
        word = str(src[i:i+length])  # Parçalanmış veri
        printable = word.translate(HEX_FILTER)  # Yazdırılabilir karakterler
        hexa = ' '.join([f'{ord(c):02X}' for c in word])  # Hexadecimal karşılıkları

        # Hexadecimal değerlerin genişliği
        hexwidth = length * 3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')

    # Sonuçları ekrana yazdır veya döndür
    if show:
        for line in results:
            print(line)
    else:
        return results
