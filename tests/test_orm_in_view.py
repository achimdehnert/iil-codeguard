"""Tests for SL-001..006 ORM-in-view detection.

Uses tmp_path fixture to write synthetic Django views and assert findings.
"""

from __future__ import annotations

from pathlib import Path

from iil_codeguard.checkers import orm_in_view


def _write(tmp: Path, name: str, source: str) -> Path:
    f = tmp / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(source, encoding="utf-8")
    return f


# SL-001 -------------------------------------------------------------------

def test_should_detect_orm_in_fbv(tmp_path):
    f = _write(tmp_path, "views.py", """
def trip_list(request):
    trips = Trip.objects.filter(active=True)
    return render(request, "trips.html", {"trips": trips})
""")
    findings = orm_in_view.check_file(f)
    sl001 = [x for x in findings if x.rule_id == "SL-001"]
    assert len(sl001) == 1
    assert sl001[0].context["model"] == "Trip"


def test_should_detect_orm_in_cbv_form_valid(tmp_path):
    f = _write(tmp_path, "views.py", """
class WorldCreateView(CreateView):
    def form_valid(self, form):
        world = World.objects.create(**form.cleaned_data)
        return super().form_valid(form)
""")
    findings = orm_in_view.check_file(f)
    sl001 = [x for x in findings if x.rule_id == "SL-001"]
    assert len(sl001) == 1
    assert sl001[0].context["model"] == "World"
    assert "form_valid" in sl001[0].message


def test_should_detect_orm_in_async_view(tmp_path):
    f = _write(tmp_path, "views.py", """
async def trip_async(request):
    trip = await Trip.objects.aget(pk=1)
    return JsonResponse({"id": trip.id})
""")
    findings = orm_in_view.check_file(f)
    sl001 = [x for x in findings if x.rule_id == "SL-001"]
    assert len(sl001) == 1
    assert "async" in sl001[0].message


def test_should_not_flag_clean_view(tmp_path):
    f = _write(tmp_path, "views.py", """
from .services import trip_service

def trip_list(request):
    trips = trip_service.list_active(request.user)
    return render(request, "trips.html", {"trips": trips})
""")
    findings = orm_in_view.check_file(f)
    sl001 = [x for x in findings if x.rule_id == "SL-001"]
    assert sl001 == []


# SL-002 -------------------------------------------------------------------

def test_should_detect_transaction_atomic_in_view(tmp_path):
    f = _write(tmp_path, "views.py", """
from django.db import transaction

def create_trip(request):
    with transaction.atomic():
        Trip.objects.create(name="x")
""")
    findings = orm_in_view.check_file(f)
    sl002 = [x for x in findings if x.rule_id == "SL-002"]
    assert len(sl002) == 1


# SL-003 -------------------------------------------------------------------

def test_should_warn_on_select_related_in_view(tmp_path):
    f = _write(tmp_path, "views.py", """
def trip_detail(request, pk):
    trip = Trip.objects.select_related("user").get(pk=pk)
    return render(request, "trip.html", {"trip": trip})
""")
    findings = orm_in_view.check_file(f)
    sl003 = [x for x in findings if x.rule_id == "SL-003"]
    assert len(sl003) == 1


# SL-004 -------------------------------------------------------------------

def test_should_warn_on_model_import_in_view(tmp_path):
    f = _write(tmp_path, "views.py", """
from .models import Trip

def trip_list(request):
    pass
""")
    findings = orm_in_view.check_file(f)
    sl004 = [x for x in findings if x.rule_id == "SL-004"]
    assert len(sl004) == 1
    assert sl004[0].context["name"] == "Trip"


# SL-005 -------------------------------------------------------------------

def test_should_detect_raw_sql(tmp_path):
    f = _write(tmp_path, "views.py", """
def trip_raw(request):
    rows = Trip.objects.raw("SELECT * FROM trips_trip")
""")
    findings = orm_in_view.check_file(f)
    sl005 = [x for x in findings if x.rule_id == "SL-005"]
    assert len(sl005) == 1


def test_should_detect_connection_cursor(tmp_path):
    f = _write(tmp_path, "views.py", """
from django.db import connection

def trip_raw(request):
    with connection.cursor() as cur:
        cur.execute("SELECT 1")
""")
    findings = orm_in_view.check_file(f)
    sl005 = [x for x in findings if x.rule_id == "SL-005"]
    assert len(sl005) == 1


# Non-view files -----------------------------------------------------------

def test_should_skip_non_view_files(tmp_path):
    f = _write(tmp_path, "services.py", """
def list_active():
    return Trip.objects.filter(active=True)
""")
    findings = orm_in_view.check_file(f)
    assert findings == []


# Resilience ----------------------------------------------------------------

def test_should_handle_syntax_error_gracefully(tmp_path):
    f = _write(tmp_path, "views.py", "def broken(:\n  pass\n")
    findings = orm_in_view.check_file(f)
    assert findings == []
