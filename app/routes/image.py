from flask import  make_response, request
from flask_restx import Resource, Namespace
import os
from app.config import Config
from app.utils import get_logger
from app.utils.signing import verify_image
from werkzeug.utils import secure_filename

ns = Namespace('image', description="截图信息")

logger = get_logger()

def allowed_file(filename):
    ALLOWED_EXTENSIONS = ['jpg','png']
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@ns.route('/<string:task_id>/<string:file_name>')
class ARLImage(Resource):

    def get(self, task_id, file_name):
        # 截图 URL 在落库时已带 ?sign=<hmac>（见 utils/signing.py），
        # 前端 <img> 无法携带 Token 头，故用签名而非 @auth 做访问控制
        if not verify_image(task_id, file_name, request.args.get("sign")):
            return make_response("", 403)
        task_id = secure_filename(task_id)
        file_name = secure_filename(file_name)
        if not allowed_file(file_name):
            return
        imgpath = os.path.join(Config.SCREENSHOT_DIR,
                               '{task_id}/{file_name}'.format(task_id=task_id,
                                                              file_name=file_name))
        if not os.path.exists(imgpath) and file_name.lower().endswith('.jpg'):
            png_name = file_name[:-4] + '.png'
            imgpath = os.path.join(Config.SCREENSHOT_DIR, task_id, png_name)
        if os.path.exists(imgpath):
            with open(imgpath, "rb") as image_file:
                image_data = image_file.read()
            response = make_response(image_data)
            response.headers['Content-Type'] = (
                'image/png' if image_data.startswith(b'\x89PNG') else 'image/jpeg')
            return response
        else:
            with open(Config.SCREENSHOT_FAIL_IMG, "rb") as image_file:
                image_data = image_file.read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response
