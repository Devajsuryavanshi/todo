# Generated by Django 3.0.7 on 2020-06-30 11:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('todo', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='todo',
            name='completedTime',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]