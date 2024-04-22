from django.views.generic import TemplateView


class IndexView(TemplateView):
    template_name = "exinakai/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["action"] = self.request.GET.get("action", None)
        return context
