"""
Management command to sync connection metadata from OAuth server.
"""
from django.core.management.base import BaseCommand
from django.db.models import Count
from svasetting.models import UserAppConnection
from svasetting.connection_registry import connection_registry
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Sync connection metadata from OAuth server'

    def add_arguments(self, parser):
        parser.add_argument(
            '--client-id',
            type=str,
            help='Sync specific client_id only',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Sync all apps',
        )

    def handle(self, *args, **options):
        client_id = options.get('client_id')
        sync_all = options.get('all', False)
        
        if client_id:
            # Sync specific app
            self.stdout.write(f'Syncing metadata for {client_id}...')
            metadata = connection_registry.sync_app_metadata_from_oauth(client_id)
            if metadata:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully synced {client_id}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'Failed to sync {client_id}')
                )
        elif sync_all:
            # Sync all unique apps
            unique_apps = (
                UserAppConnection.objects
                .values('client_id')
                .annotate(count=Count('id'))
                .order_by('-count')
            )
            
            total = unique_apps.count()
            self.stdout.write(f'Syncing {total} apps...')
            
            success = 0
            failed = 0
            
            for app in unique_apps:
                client_id = app['client_id']
                self.stdout.write(f'Syncing {client_id}...')
                
                metadata = connection_registry.sync_app_metadata_from_oauth(client_id)
                if metadata:
                    success += 1
                else:
                    failed += 1
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Sync complete: {success} succeeded, {failed} failed'
                )
            )
        else:
            self.stdout.write(
                self.style.ERROR(
                    'Please specify --client-id or --all'
                )
            )

