# Generated by Django 4.1 on 2022-10-14 09:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('goals', '0001_initial'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='goalcategory',
            unique_together=set(),
        ),
    ]
