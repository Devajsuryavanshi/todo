from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login,logout, authenticate
from .forms import TodoForm
from .models import Todo
from django.utils import timezone
from django.contrib.auth.decorators import login_required

def signupuser(request):

    if request.method == 'GET':
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
    else:
        #Create a new user
        if request.POST['password1'] == request.POST['password2']:
            try:
               user = User.objects.create_user(request.POST['username'], password= request.POST['password1'])
               user.save()
               login(request, user)
               return redirect('currenttodo')
            except IntegrityError:
                return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': "Username is already taken!"})
        else:
           return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': "Password did not match!"})

@login_required
def currenttodo(request):
    todos = Todo.objects.filter(user = request.user, completedTime__isnull = True)
    return render(request, 'todo/current.html', {'todos': todos})

@login_required
def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return render(request, 'todo/home.html')

def loginuser(request):
    if request.method == 'GET':
        return render(request, 'todo/loginuser.html', {'form':AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password= request.POST['password'])
        if user is None:
            return render(request, 'todo/loginuser.html', {'form':AuthenticationForm(), 'error': 'username or password is incorrect'})
        else:
            login(request,user)
            return redirect('home')


def home(request):
    return render(request, 'todo/home.html')

@login_required
def createtodo(request):
    if request.method == 'GET':
        return render(request, 'todo/create.html', {'form': TodoForm})
    else:
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
            return redirect('currenttodo')
        except ValueError:
             return render(request, 'todo/create.html', {'form': TodoForm, 'error': "Bad data passed, Try again!"})

@login_required
def viewtodo(request, todo_pk):
    todos = get_object_or_404(Todo, pk=todo_pk, user = request.user)
    if request.method == 'GET':
        form = TodoForm(instance=todos)
        return render(request, 'todo/viewtodo.html', {'form': form, 'todo': todos})
    else:
        try:
            form = TodoForm(request.POST, instance=todos)
            form.save()
            return redirect('currenttodo')
        except ValueError:
             return render(request, 'todo/viewtodo.html', {'form': form, 'todo': todos, 'error': "Bad data passed, Try again!"})

@login_required
def completed(request, todo_pk):
    todos = get_object_or_404(Todo, pk=todo_pk, user = request.user)
    if request.method == 'POST':
        todos.completedTime = timezone.now()
        todos.save()
        return redirect('currenttodo')

@login_required
def deleted(request, todo_pk):
    todos = get_object_or_404(Todo, pk=todo_pk, user = request.user)
    if request.method == 'POST':
        todos.delete()
        return redirect('currenttodo')

@login_required
def completedtodos(request):
    todos = Todo.objects.filter(user = request.user, completedTime__isnull = False).order_by('-completedTime')
    return render(request, 'todo/completedtodos.html', {'todos': todos})
        
def search(request):
    if request.method == 'GET':
        m = request.GET.get("searched")
        searchedtodo = Todo.objects.filter(user = request.user, title__icontains = m)
        if searchedtodo.exists():
            return render(request, 'todo/searched.html', {'todo':searchedtodo})
        else:
            return render(request, 'todo/searched.html', {'error':"not found"})