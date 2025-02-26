import socket

MESSAGE = "TEST"
UDP_IP = "192.168.1.1"  # Kendi ağındaki başka bir cihazın IP adresini yaz
UDP_PORT = 65212

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(bytes(MESSAGE, "utf-8"), (UDP_IP, UDP_PORT))
print("UDP packet sent")
