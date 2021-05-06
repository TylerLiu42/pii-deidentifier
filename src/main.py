import os

from flask import Flask, request, jsonify
from google.cloud import storage
from google.cloud import dlp
from google.cloud import pubsub

app = Flask(__name__)

CLOUD_STORAGE_BUCKET = os.environ['CLOUD_STORAGE_BUCKET']
PROJECT_ID = 'tidal-copilot-312621'
"""The bucket the to-be-scanned files are uploaded to."""
STAGING_BUCKET = 'tl-quarantine-1'
"""The bucket to move "sensitive" files to."""
SENSITIVE_BUCKET = 'tl-sensitive-1'
"""The bucket to move "non sensitive" files to."""
NONSENSITIVE_BUCKET = 'tl-non-sensitive-1'
""" Pub/Sub topic to notify once the  DLP job completes."""
PUB_SUB_TOPIC = 'classification'
"""The minimum_likelihood (Enum) required before returning a match"""
"""For more info visit: https://cloud.google.com/dlp/docs/likelihood"""
MIN_LIKELIHOOD = 'POSSIBLE'
"""The maximum number of findings to report (0 = server maximum)"""
MAX_FINDINGS = 0
"""The infoTypes of information to match"""
"""For more info visit: https://cloud.google.com/dlp/docs/concepts-infotypes"""
INFO_TYPES = [
    'FIRST_NAME', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'US_SOCIAL_SECURITY_NUMBER'
]

# End of User-configurable Constants
# ----------------------------------

# Initialize the Google Cloud client libraries
dlp = dlp.DlpServiceClient()
storage_client = storage.Client()
publisher = pubsub.PublisherClient()
subscriber = pubsub.SubscriberClient()

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file is None:
        return jsonify(message="File not found"), 400
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
    return jsonify(message="Success"), 200


def create_dlp_job(data, done):
  """This function is triggered by new files uploaded to the designated Cloud Storage quarantine/staging bucket.

       It creates a dlp job for the uploaded file.
    Arg:
       data: The Cloud Storage Event
    Returns:
        None. Debug information is printed to the log.
    """
  # Get the targeted file in the quarantine bucket
  file_name = data['name']
  print('Function triggered for file [{}]'.format(file_name))

  # Prepare info_types by converting the list of strings (INFO_TYPES) into a list of dictionaries
  info_types = [{'name': info_type} for info_type in INFO_TYPES]

  # Convert the project id into a full resource id.
  parent = f"projects/{PROJECT_ID}"

  # Construct the configuration dictionary.
  inspect_job = {
      'inspect_config': {
          'info_types': info_types,
          'min_likelihood': MIN_LIKELIHOOD,
          'limits': {
              'max_findings_per_request': MAX_FINDINGS
          },
      },
      'storage_config': {
          'cloud_storage_options': {
              'file_set': {
                  'url':
                      'gs://{bucket_name}/{file_name}'.format(
                          bucket_name=STAGING_BUCKET, file_name=file_name)
              }
          }
      },
      'actions': [{
          'pub_sub': {
              'topic':
                  'projects/{project_id}/topics/{topic_id}'.format(
                      project_id=PROJECT_ID, topic_id=PUB_SUB_TOPIC)
          }
      }]
  }

  # Create the DLP job and let the DLP api processes it.
  try:
    dlp.create_dlp_job(parent=(parent), inspect_job=(inspect_job))
    print('Job created by create_DLP_job')
  except Exception as e:
    print(e)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)