from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('identity_canvas', '0006_remove_documentverification_digilocker_access_token_and_more'),
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='VerificationCanvas',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('encrypted_blocks', models.TextField(help_text='Encrypted JSON array of verification blocks')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('version', models.IntegerField(default=1)),
                ('user', models.OneToOneField(on_delete=models.deletion.CASCADE, related_name='verification_canvas', to='authentication.zkuser')),
            ],
            options={
                'verbose_name': 'Verification Canvas',
                'verbose_name_plural': 'Verification Canvases',
                'db_table': 'verification_canvas',
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='VerificationCanvasHistory',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('encrypted_blocks_snapshot', models.TextField()),
                ('version', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('action', models.CharField(blank=True, help_text='Action that created this version (create, update, delete)', max_length=50, null=True)),
                ('canvas', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='history', to='identity_canvas.verificationcanvas')),
            ],
            options={
                'verbose_name': 'Verification Canvas History',
                'verbose_name_plural': 'Verification Canvas Histories',
                'db_table': 'verification_canvas_history',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='verificationcanvashistory',
            index=models.Index(fields=['canvas', '-created_at'], name='verification_canvas_hist_idx'),
        ),
    ]

