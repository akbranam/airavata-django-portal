from django.db import models


# Create your models here.
class WorkspacePreferences(models.Model):
    username = models.CharField(max_length=64, primary_key=True)
    most_recent_project_id = models.CharField(max_length=64)

    @classmethod
    def create(self, username):
        return WorkspacePreferences(username=username)


class User_Files(models.Model):
    username = models.CharField(max_length=64)
    file_path = models.TextField()
    file_dpu = models.CharField(max_length=255, primary_key=True)

    class Meta:
        indexes = [
            # FIXME: ideally we would include file_path in the index to make
            # lookups faster, but Django/MariaDB don't support key length on a
            # TEXT column which is required to create an index
            models.Index(fields=['username'], name='username_idx')
        ]
