# Generated by Django 4.2.4 on 2023-08-16 13:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('knowledge', '0004_remove_kbentry_modified_datetime'),
    ]

    operations = [
        migrations.AddField(
            model_name='kbentry',
            name='modified_datetime',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
