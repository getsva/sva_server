from django.apps import AppConfig


class IdentityCanvasConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'identity_canvas'
    verbose_name = 'Identity Canvas'
    
    def ready(self):
        # Import signals to ensure they're connected
        import identity_canvas.models  # noqa

