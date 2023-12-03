from flask import Flask, request, jsonify

app = Flask(__name__)

id_token_list = []

@app.route('/data/id_token', methods=['POST'])
def post_id_token_from_browser():
    data = request.json

    if data.get('id_token') is not None:
        id_token_list.append({"id_token": data.get('id_token')})
    
    return "ok", 200

@app.route('/data/id_token', methods=['GET'])
def get_id_token():
    if len(id_token_list) == 0:
        return "no data", 200
    return id_token_list[len(id_token_list)-1], 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6666, debug=False)