# Generated by Django 4.2.4 on 2023-08-14 10:26

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('kb_app', '0002_kbentry_rating_kbentry_views'),
    ]

    operations = [
        migrations.AlterField(
            model_name='audit',
            name='kb_entry',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='kb_app.kbentry'),
        ),
    ]
