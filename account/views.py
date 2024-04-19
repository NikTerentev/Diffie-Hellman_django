import hashlib
import json

from Crypto.Util import number
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from pyDH import DiffieHellman

from .aes import *
from .forms import CustomAuthenticationForm
from .forms import UserRegistrationForm, PhotoForm
from .models import Profile, Photo


class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = number.getRandomRange(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def get_shared_secret(self, partner_public_key):
        shared_secret = pow(partner_public_key, self.private_key, self.p)
        return str(shared_secret)


@csrf_exempt
def get_dh_data(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        client_public_key = int(data.get('publicKeyClient'))
        p = int(data.get('p'))
        g = int(data.get('g'))

        dh = DiffieHellman(p, g)

        server_public_key = dh.public_key
        shared_secret = dh.get_shared_secret(client_public_key)

        request.session['shared_secret'] = shared_secret

        return JsonResponse(
            {'serverPublicKey': server_public_key})


def login(request):
    if request.method == 'POST':

        encrypted_user_username = request.POST['username']
        encrypted_user_password = request.POST['password']

        shared_secret = request.session.get('shared_secret')

        user_username = decrypt(encrypted_user_username,
                                shared_secret.encode()).decode()
        user_password = decrypt(encrypted_user_password,
                                shared_secret.encode()).decode()
        hashed_user_username = hashlib.sha256(
            user_username.encode()).hexdigest()

        hashed_user_password = hashlib.sha256(
            user_password.encode()).hexdigest()

        user = authenticate(request, username=hashed_user_username,
                            password=hashed_user_password,
                            shared_secret_key=shared_secret)
        if user is not None:
            auth_login(request, user)
            return render(request, 'account/dashboard.html')
        else:
            messages.error(request, 'Wrong login or password!')
            form = CustomAuthenticationForm()
            return render(request, 'account/login.html', {'form': form})
    else:
        form = CustomAuthenticationForm()
    return render(request, 'account/login.html', {'form': form})


@login_required
def dashboard(request):
    return render(request,
                  'account/dashboard.html',
                  {'section': 'dashboard'})


@login_required
def images(request):
    user_profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        encrypted_image_data = request.POST.get('encryptedImageData')
        shared_secret = request.session.get('shared_secret')

        # Расшифровка изображения
        decrypted_image_data = decrypt(encrypted_image_data,
                                       shared_secret.encode())

        # Преобразование расшифрованных данных в объект изображения
        image_file = ContentFile(base64.b64decode(decrypted_image_data),
                                 name='uploaded_image.jpg')

        # Создание объекта Photo и сохранение в базу данных
        photo = Photo(image=image_file)
        photo.save()
        user_profile.photos.add(photo)
        return JsonResponse(
            {'success': True, 'message': 'Photo uploaded successfully'})

    else:
        form = PhotoForm()

    return render(request, 'account/images.html', {'form': form})


@login_required
def images_json(request):
    user_profile, created = Profile.objects.get_or_create(user=request.user)

    user_images = user_profile.photos.all()

    if len(user_images) > 0:
        shared_secret = request.session.get('shared_secret')

        encrypted_images = []

        for original_image in user_images:
            image_bytes = original_image.image.read()
            encrypted_image = encrypt(image_bytes, shared_secret.encode())

            encrypted_images.append({
                'id': original_image.id,
                'image': encrypted_image.decode('utf-8'),
            })

        return JsonResponse({'success': True, 'images': encrypted_images})

    return JsonResponse({'success': True, 'images': []})


@login_required
def delete_photo(request, photo_id):
    photo = get_object_or_404(Photo, id=photo_id)
    photo.delete()

    if request.headers.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
        return JsonResponse({'message': 'Photo deleted successfully.'})
    else:
        # Если это не AJAX-запрос, перенаправляем пользователя на страницу images
        return render(request, 'account/images.html', {'section': 'images',
                                                       'images': request.user.profile.photos.all()})


def register(request):
    if request.method == 'POST':
        # Создаем копию словаря request.POST
        modified_post_data = request.POST.copy()

        encrypted_user_username = modified_post_data['username']
        encrypted_user_password = modified_post_data['password']

        shared_secret = request.session.get('shared_secret')

        user_username = decrypt(encrypted_user_username,
                                shared_secret.encode()).decode()
        user_password = decrypt(encrypted_user_password,
                                shared_secret.encode()).decode()

        hashed_user_username = hashlib.sha256(
            user_username.encode()).hexdigest()

        hashed_user_password = hashlib.sha256(
            user_password.encode()).hexdigest()

        # Вносим изменения в копию словаря
        modified_post_data['username'] = hashed_user_username
        modified_post_data['password'] = hashed_user_password
        modified_post_data['password2'] = hashed_user_password

        user_form = UserRegistrationForm(modified_post_data)
        if user_form.is_valid():
            # Создать новый объект пользователя,
            # но пока не сохранять его
            new_user = user_form.save(commit=False)
            # Установить выбранный пароль

            new_user.set_password(
                user_form.cleaned_data['password']
            )
            # Сохранить объект User
            new_user.save()
            # Сохранить открытый ключ и зашифрованный закрытый ключ
            Profile.objects.create(user=new_user)
            return render(request,
                          'account/register_done.html',
                          {'new_user': new_user})
    else:
        user_form = UserRegistrationForm()
    return render(request,
                  'account/register.html',
                  {'user_form': user_form})
