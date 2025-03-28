import paramiko
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from threading import Lock

paramiko.util.log_to_file("/paramiko.log")
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://www.netops.u51.com"}})
socketio = SocketIO(app, cors_allowed_origins="http://www.netops.u51.com")

sessions = {}
lock = Lock()

@app.route('/')
def index():
    return render_template('devices.html')

@socketio.on('start_session')
def start_session(data):
    ip = data['ip']
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Attempting to connect to {ip}")
        ssh_client.connect(
            ip,
            username='51en',
            password='51en@SWP20',
            look_for_keys=False,
            allow_agent=False,
            disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"])
        )
        transport = ssh_client.get_transport()
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()

        sid = request.sid

        def receive_data(sid):
            while True:
                if channel.recv_ready():
                    output = channel.recv(1024).decode('utf-8')
                    socketio.emit('output', output, to=sid)

        with lock:
            sessions[sid] = (ssh_client, channel)
        
        socketio.start_background_task(receive_data, sid)
        emit('session_started', {'status': 'success'})
    except Exception as e:
        print(f"Error connecting to {ip}: {str(e)}")
        emit('output', f'Error connecting to {ip}: {str(e)}')

@socketio.on('input')
def handle_input(data):
    with lock:
        _, channel = sessions.get(request.sid, (None, None))
    if channel:
        channel.send(data)
    else:
        emit('output', 'No existing session')

@socketio.on('end_session')
def end_session():
    with lock:
        ssh_client, channel = sessions.pop(request.sid, (None, None))
    if channel:
        channel.close()
    if ssh_client:
        ssh_client.close()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

