from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Employee, SecurityEvent, Incident, User, AuditLog
from app.schemas import EmployeeCreateRequest, EmployeeUpdateRequest, EmployeeResponse, SecurityEventResponse
from app.utils.auth import require_roles, require_authenticated_user, ADMIN_ROLES, STAFF_ROLES

router = APIRouter(prefix="/employees", tags=["Employee Management"])

@router.get("", response_model=List[EmployeeResponse], dependencies=[Depends(require_roles(STAFF_ROLES))])
def list_employees(
    search: Optional[str] = None,
    department: Optional[str] = None,
    policy: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Employee)
    if department and department != "All":
        query = query.filter(Employee.department == department)
    if policy and policy != "All":
        query = query.filter(Employee.monitoring_policy == policy)
    if is_active is not None:
        query = query.filter(Employee.is_active == is_active)
    if search:
        s = f"%{search}%"
        query = query.filter(
            Employee.employee_id.ilike(s) |
            Employee.full_name.ilike(s) |
            Employee.company_email.ilike(s) |
            Employee.department.ilike(s) |
            Employee.role_title.ilike(s)
        )
    return query.order_by(Employee.employee_id.asc()).offset(offset).limit(limit).all()

@router.post("", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
def create_employee(
    payload: EmployeeCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Super Admin", "Security Administrator"]))
):
    # 1. Check duplicate employee_id
    existing_id = db.query(Employee).filter(Employee.employee_id == payload.employee_id.strip()).first()
    if existing_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An employee with ID '{payload.employee_id}' already exists."
        )

    # 2. Check duplicate email
    email_clean = payload.company_email.strip().lower()
    existing_email = db.query(Employee).filter(Employee.company_email == email_clean).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An employee with company email '{email_clean}' already exists."
        )

    emp = Employee(
        employee_id=payload.employee_id.strip().upper(),
        full_name=payload.full_name.strip(),
        company_email=email_clean,
        phone_number=payload.phone_number.strip() if payload.phone_number else None,
        department=payload.department.strip(),
        role_title=payload.role_title.strip(),
        monitoring_policy=payload.monitoring_policy,
        is_active=True,
        risk_score=0
    )
    db.add(emp)

    audit = AuditLog(
        action="EMPLOYEE_CREATED",
        actor=current_user.email,
        resource_type="Employee",
        resource_id=emp.employee_id,
        details=f"Created employee record for {emp.full_name} ({emp.company_email}) with policy '{emp.monitoring_policy}'."
    )
    db.add(audit)
    db.commit()
    db.refresh(emp)

    return EmployeeResponse.model_validate(emp)

@router.get("/{employee_id}", response_model=EmployeeResponse, dependencies=[Depends(require_roles(STAFF_ROLES))])
def get_employee_detail(employee_id: str, db: Session = Depends(get_db)):
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail=f"Employee '{employee_id}' not found.")
    return EmployeeResponse.model_validate(emp)

@router.patch("/{employee_id}", response_model=EmployeeResponse)
def update_employee(
    employee_id: str,
    payload: EmployeeUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Super Admin", "Security Administrator"]))
):
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail=f"Employee '{employee_id}' not found.")

    if payload.full_name is not None:
        emp.full_name = payload.full_name.strip()
    if payload.phone_number is not None:
        emp.phone_number = payload.phone_number.strip()
    if payload.department is not None:
        emp.department = payload.department.strip()
    if payload.role_title is not None:
        emp.role_title = payload.role_title.strip()
    if payload.monitoring_policy is not None:
        emp.monitoring_policy = payload.monitoring_policy
    if payload.is_active is not None:
        emp.is_active = payload.is_active

    emp.updated_at = datetime.now(timezone.utc)

    audit = AuditLog(
        action="EMPLOYEE_UPDATED",
        actor=current_user.email,
        resource_type="Employee",
        resource_id=emp.employee_id,
        details=f"Updated employee record {emp.employee_id} (Active: {emp.is_active}, Policy: {emp.monitoring_policy})."
    )
    db.add(audit)
    db.commit()
    db.refresh(emp)

    return EmployeeResponse.model_validate(emp)

@router.post("/bulk-import")
def bulk_import_employees(
    records: List[EmployeeCreateRequest],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Super Admin", "Security Administrator"]))
):
    imported = 0
    skipped_duplicates = 0
    errors = []

    for idx, r in enumerate(records):
        emp_id = r.employee_id.strip().upper()
        email_clean = r.company_email.strip().lower()

        # Check duplicates
        existing = db.query(Employee).filter(
            (Employee.employee_id == emp_id) | (Employee.company_email == email_clean)
        ).first()

        if existing:
            skipped_duplicates += 1
            continue

        try:
            new_emp = Employee(
                employee_id=emp_id,
                full_name=r.full_name.strip(),
                company_email=email_clean,
                phone_number=r.phone_number.strip() if r.phone_number else None,
                department=r.department.strip(),
                role_title=r.role_title.strip(),
                monitoring_policy=r.monitoring_policy,
                is_active=True,
                risk_score=0
            )
            db.add(new_emp)
            imported += 1
        except Exception as e:
            errors.append(f"Row {idx+1}: {str(e)}")

    audit = AuditLog(
        action="EMPLOYEE_BULK_IMPORT",
        actor=current_user.email,
        resource_type="Employee",
        resource_id=f"BATCH-{len(records)}",
        details=f"Bulk imported {imported} employees, skipped {skipped_duplicates} duplicates."
    )
    db.add(audit)
    db.commit()

    return {
        "status": "success",
        "imported_count": imported,
        "skipped_duplicates": skipped_duplicates,
        "errors": errors
    }

@router.get("/{employee_id}/events", response_model=List[SecurityEventResponse])
def get_employee_security_events(employee_id: str, db: Session = Depends(get_db),
                                 current_user: User = Depends(require_authenticated_user)):
    if current_user.role not in STAFF_ROLES and current_user.employee_id != employee_id:
        raise HTTPException(status_code=403, detail="You can only view your own security events.")
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail=f"Employee '{employee_id}' not found.")

    conditions = (SecurityEvent.employee_id == emp.employee_id) | (SecurityEvent.user_account.ilike(f"%{emp.company_email}%"))
    first_name = (emp.full_name or "").split()
    if first_name:
        conditions = conditions | SecurityEvent.user_account.ilike(f"%{first_name[0]}%")
    events = db.query(SecurityEvent).filter(conditions).order_by(SecurityEvent.timestamp.desc()).all()

    return events
