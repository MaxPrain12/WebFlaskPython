from flask import Blueprint, render_template, flash, request, jsonify
from flask.json import jsonify
from flask_login import login_required, current_user
from .models import Mensajes, Note, Mensajes
from . import db
import json

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('No puedes guardar un comentario vacio!!!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()

            flash('El comentario se a guardado con correctamente!!', category='success')
        
    return render_template("home.html", user = current_user)
@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
            return jsonify({})

@views.route('/OnlineChat', methods=['GET', 'POST'])
@login_required
def OnlineChat():
    if request.method == 'POST':
        chat = request.form.get('chat')

        if len(chat) < 1:
            flash('No se puede guardar un mensaje vacio', category='error')
        else:
            new_chat = Mensajes(data=chat, user_id=current_user.id)
            db.session.add(new_chat)
            db.session.commit()
    return render_template("OnlineChat.html", user = current_user, chat=Mensajes.query.all())