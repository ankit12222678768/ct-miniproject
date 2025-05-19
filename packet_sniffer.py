from flask import Flask, render_template, jsonify
from scapy.all import sniff

app = Flask(__name__)
packets = []

def packet_callback(packet):
    packets.append(packet.summary())
    if len(packets) > 50:
        packets.pop(0)

@app.route('/')
def index():
    print("Loading index.html...")  # Debug line
    return render_template('index.html')

@app.route('/packets')
def get_packets():
    return jsonify(packets)

def start_sniffing():
    sniff(prn=packet_callback, store=False)

if __name__ == '__main__':
    import threading
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    app.run(debug=True)
