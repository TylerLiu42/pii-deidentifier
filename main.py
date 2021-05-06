from flask import Flask, request, jsonify

app = Flask(__name__)

CLOUD_STORAGE_BUCKET = os.environ['CLOUD_STORAGE_BUCKET']

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['file']
    # Create a Cloud Storage client.
    gcs = storage.Client()

    # Get the bucket that the file will be uploaded to.
    bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)

    # Create a new blob and upload the file's content.
    blob = bucket.blob(uploaded_file.filename)

    blob.upload_from_string(
        uploaded_file.read(),
        content_type=uploaded_file.content_type
    )
    return 200, jsonify(message="Success")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)