from django.http import HttpResponse
from django.shortcuts import render, render_to_response
from django.core.files.storage import FileSystemStorage
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from django.core.files.base import ContentFile
from django.conf import settings
from django.template import RequestContext

def home(request):
    return render(request, 'home.html')

def my_encode(request):
    return render(request, 'encode.html')

def my_decode(request):
    return render(request, 'decode.html')

def encrypt(request):
    file_tag = "file_to_encrypt"

    if request.method == 'POST' and request.FILES[file_tag]:
        mode = request.POST["mode"]
        key = request.POST["key"]
        iv = request.POST["iv"]
        #block_size = 16
        myfile = request.FILES[file_tag]

        data = myfile.read()
        #print("data type", type(data))
        #data = pad(data, block_size, style='pkcs7')

        fs = FileSystemStorage()

        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)

        ciphertext = encode(data, key, mode, iv)
        #print(ciphertext)

        enc_file = ContentFile(ciphertext)
        enc_filename = fs.save("enc_" + myfile.name, enc_file)
        download_file_url = fs.url(enc_filename)

        return render(request, 'download.html', {'uploaded_file_url': uploaded_file_url,
                                                 'download_file_url': download_file_url})

    return render(request, "not_ok.html")

def decrypt(request):
    file_tag = "file_to_decrypt"

    if request.method == 'POST' and request.FILES[file_tag]:
        mode = request.POST["mode"]
        key = request.POST["key"]
        iv = request.POST["iv"]
        block_size = 16
        myfile = request.FILES[file_tag]

        data = myfile.read() ## convert byte to string
        #print("ciphertext data type", type(data))
        #print(data)

        fs = FileSystemStorage()  #location='/media'??

        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)

        text = decode(data, key, mode, iv)
        #print("decyphered data", text)
        #text = unpad(text, 16, style= 'pkcs7')

        dec_file = ContentFile(text)
        dec_filename = fs.save("dec_" + myfile.name, dec_file)
        download_file_url = fs.url(dec_filename)

        return render(request, 'download.html', {'uploaded_file_url': uploaded_file_url,
                                                 'download_file_url': download_file_url})

    return render(request, "not_ok.html")


def download(request):
    filename = request.GET['file_to_download']

    ## use application/octet-stream for content_type vs text/plain
    with open(filename, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=' + filename
        response['Content-Type'] = 'application/octet-stream; charset=utf-8'
        return response

def encode(data, key, mode, iv) :
    key = key.encode()
    iv = iv.encode()
    block_size = 16

    if mode == 'ecb':
        data = pad(data, block_size, style='pkcs7')
        encryption_suite = AES.new(key, AES.MODE_ECB)
        enc_data = encryption_suite.encrypt(data)
    elif mode == 'cbc':
        data = pad(data, block_size, style='pkcs7')
        encryption_suite = AES.new(key, AES.MODE_CBC, iv)
        enc_data = encryption_suite.encrypt(data)
    elif mode == 'cfb':
        encryption_suite = AES.new(key, AES.MODE_CFB, iv)
        enc_data = encryption_suite.encrypt(data)
    elif mode == 'ofb':
        encryption_suite = AES.new(key, AES.MODE_OFB, iv)
        enc_data = encryption_suite.encrypt(data)
    #enc_data = "This is an encrypt text demo. This is a test.\n this is a test.\n"
    return enc_data


def decode(data, key, mode, iv):
    ## Do the real decoding here
    key = key.encode()
    iv = iv.encode()
    block_size = 16

    if mode == 'ecb':
        decryption_suite = AES.new(key, AES.MODE_ECB)
        dec_data = decryption_suite.decrypt(data)
        dec_data = unpad(dec_data, block_size, style='pkcs7')
    elif mode == 'cbc':
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        dec_data = decryption_suite.decrypt(data)
        dec_data = unpad(dec_data, block_size, style='pkcs7')
    elif mode == 'cfb':
        decryption_suite = AES.new(key, AES.MODE_CFB, iv)
        dec_data = decryption_suite.decrypt(data)
    elif mode == 'ofb':
        decryption_suite = AES.new(key, AES.MODE_OFB, iv)
        dec_data = decryption_suite.decrypt(data)

    #dec_data = unpad(dec_data, block_size, style='pkcs7')

    #dec_data = "This is a decoded text giving you the original" #used for testing only
    return dec_data

def mypagenotfound(request):
    return render(request, 'error.html')

def myservererror(request):
    return render(request, 'error.html')

def mypermissiondenied(request):
    return render(request, 'error.html')

def mybadrequest(request):
    return render(request, 'error.html')