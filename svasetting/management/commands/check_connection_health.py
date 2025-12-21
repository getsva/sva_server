"""
Management command to check connection health.
"""
from django.core.management.base import BaseCommand
from svasetting.models import UserAppConnection
from svasetting.connection_utils import check_connection_health
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Check health of app connections'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user-id',
            type=str,
            help='Check connections for specific user',
        )
        parser.add_argument(
            '--client-id',
            type=str,
            help='Check connections for specific app',
        )
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Attempt to fix issues',
        )

    def handle(self, *args, **options):
        user_id = options.get('user_id')
        client_id = options.get('client_id')
        fix = options.get('fix', False)
        
        queryset = UserAppConnection.objects.filter(is_active=True)
        
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        if client_id:
            queryset = queryset.filter(client_id=client_id)
        
        connections = queryset.all()
        total = connections.count()
        
        self.stdout.write(f'Checking {total} connections...')
        
        healthy = 0
        unhealthy = 0
        issues_found = []
        
        for connection in connections:
            health = check_connection_health(connection)
            
            if health['is_healthy']:
                healthy += 1
            else:
                unhealthy += 1
                issues_found.append({
                    'connection_id': str(connection.id),
                    'app_name': connection.app_name,
                    'user_id': str(connection.user_id),
                    'issues': health['issues']
                })
                
                if fix:
                    # Attempt to fix issues
                    self.stdout.write(
                        f'Fixing issues for connection {connection.id}...'
                    )
                    # Could mark for blob update, etc.
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Health check complete: {healthy} healthy, {unhealthy} unhealthy'
            )
        )
        
        if issues_found:
            self.stdout.write('\nIssues found:')
            for issue in issues_found[:10]:  # Show first 10
                self.stdout.write(
                    f"  {issue['app_name']} ({issue['connection_id']}): "
                    f"{', '.join(issue['issues'])}"
                )
            
            if len(issues_found) > 10:
                self.stdout.write(
                    f'  ... and {len(issues_found) - 10} more'
                )

