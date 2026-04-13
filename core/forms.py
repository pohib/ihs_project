from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField(
        label="Выберите файл (CSV или JSON)",
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': '.csv, .json',
        })
    )

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            extension = file.name.split('.')[-1].lower()
            if extension not in ['csv', 'json']:
                raise forms.ValidationError("Система поддерживает форматы CSV и JSON.")
        return file