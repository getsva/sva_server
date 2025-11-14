# Generated migration for Identity Canvas

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('authentication', '0005_zkemailverificationtoken_device_fingerprint_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='IdentityCanvas',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('encrypted_blocks', models.TextField(help_text='Encrypted JSON array of identity blocks')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('version', models.IntegerField(default=1)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='identity_canvas', to='authentication.zkuser')),
            ],
            options={
                'verbose_name': 'Identity Canvas',
                'verbose_name_plural': 'Identity Canvases',
                'db_table': 'identity_canvas',
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='CanvasHistory',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('encrypted_blocks_snapshot', models.TextField()),
                ('version', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('action', models.CharField(blank=True, help_text="Action that created this version (create, update, delete)", max_length=50, null=True)),
                ('canvas', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='history', to='identity_canvas.identitycanvas')),
            ],
            options={
                'verbose_name': 'Canvas History',
                'verbose_name_plural': 'Canvas Histories',
                'db_table': 'canvas_history',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='canvashistory',
            index=models.Index(fields=['canvas', '-created_at'], name='canvas_his_canvas__idx'),
        ),
    ]

