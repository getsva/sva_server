# Generated migration for verification_token on ConnectedService

import secrets
from django.db import migrations, models


def populate_verification_tokens(apps, schema_editor):
    ConnectedService = apps.get_model('svasetting', 'ConnectedService')
    for service in ConnectedService.objects.all():
        service.verification_token = secrets.token_urlsafe(32)
        service.save(update_fields=['verification_token'])


class Migration(migrations.Migration):

    dependencies = [
        ('svasetting', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectedservice',
            name='verification_token',
            field=models.CharField(db_index=True, editable=False, max_length=64, null=True, unique=True),
        ),
        migrations.RunPython(populate_verification_tokens, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='connectedservice',
            name='verification_token',
            field=models.CharField(db_index=True, editable=False, max_length=64, unique=True),
        ),
    ]
