import React, { useState, useEffect } from 'react';
import {
  Users, UserPlus, Search, Filter, CheckCircle2, XCircle,
  Edit, Trash2, ChevronLeft, ChevronRight, Mail, Phone,
  Building, Briefcase, RefreshCw, Upload, AlertTriangle
} from 'lucide-react';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { Employee, Severity } from '../types';

export const EmployeeManagementPage: React.FC = () => {
  const { theme } = useTheme();
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('All Departments');
  const [statusFilter, setStatusFilter] = useState('All Status');
  const [currentPage, setCurrentPage] = useState(1);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedEmp, setSelectedEmp] = useState<Employee | null>(null);

  // Form
  const [formData, setFormData] = useState({
    employee_id: '',
    full_name: '',
    company_email: '',
    phone_number: '',
    department: 'IT',
    role_title: 'Employee',
    monitoring_policy: 'Standard' as 'Strict' | 'High' | 'Standard' | 'Low',
  });
  const [formError, setFormError] = useState<string | null>(null);

  // Seed with realistic records matching Screen 3 if empty
  const defaultMockEmployees: Employee[] = [
    { id: 1, employee_id: 'EMP001', full_name: 'Rahul Kumar', company_email: 'rahul.k@company.com', phone_number: '+91 98765 43210', department: 'IT', role_title: 'Employee', monitoring_policy: 'Standard', is_active: true, risk_level: 'High', created_at: '2026-01-10T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 2, employee_id: 'EMP002', full_name: 'Priya Sharma', company_email: 'priya.s@company.com', phone_number: '+91 91234 56789', department: 'HR', role_title: 'Employee', monitoring_policy: 'Standard', is_active: true, risk_level: 'Critical', created_at: '2026-01-12T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 3, employee_id: 'EMP003', full_name: 'Arun Mehta', company_email: 'arun.m@company.com', phone_number: '+91 87654 32109', department: 'Finance', role_title: 'Employee', monitoring_policy: 'Strict', is_active: true, risk_level: 'High', created_at: '2026-02-01T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 4, employee_id: 'EMP004', full_name: 'Divya R', company_email: 'divya.r@company.com', phone_number: '+91 93456 78901', department: 'Marketing', role_title: 'Employee', monitoring_policy: 'Standard', is_active: true, risk_level: 'Low', created_at: '2026-02-15T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 5, employee_id: 'EMP005', full_name: 'Karan V', company_email: 'karan.v@company.com', phone_number: '+91 99887 76655', department: 'IT', role_title: 'Employee', monitoring_policy: 'High', is_active: false, risk_level: 'Medium', created_at: '2026-03-01T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 6, employee_id: 'EMP006', full_name: 'Sneha T', company_email: 'sneha.t@company.com', phone_number: '+91 91765 44321', department: 'HR', role_title: 'Employee', monitoring_policy: 'Standard', is_active: true, risk_level: 'Low', created_at: '2026-03-10T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 7, employee_id: 'EMP007', full_name: 'Adithya R', company_email: 'adithya.r@company.com', phone_number: '+91 97890 12345', department: 'Finance', role_title: 'Employee', monitoring_policy: 'Strict', is_active: true, risk_level: 'Medium', created_at: '2026-04-01T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
    { id: 8, employee_id: 'EMP008', full_name: 'Nithya S', company_email: 'nithya.s@company.com', phone_number: '+91 95567 88990', department: 'Marketing', role_title: 'Employee', monitoring_policy: 'Standard', is_active: true, risk_level: 'Low', created_at: '2026-04-12T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' },
  ];

  const loadEmployees = async () => {
    setLoading(true);
    try {
      const data = await api.getEmployees({
        department: departmentFilter !== 'All Departments' ? departmentFilter : undefined,
        search: search.trim() || undefined,
      });
      if (data && data.length > 0) {
        setEmployees(data);
      } else {
        setEmployees(defaultMockEmployees);
      }
    } catch (err) {
      console.warn('Using mock employee records:', err);
      setEmployees(defaultMockEmployees);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEmployees();
  }, [departmentFilter, statusFilter]);

  const filteredEmployees = employees.filter((emp) => {
    const matchesSearch =
      !search ||
      emp.full_name.toLowerCase().includes(search.toLowerCase()) ||
      emp.company_email.toLowerCase().includes(search.toLowerCase()) ||
      emp.department.toLowerCase().includes(search.toLowerCase());
    const matchesDept =
      departmentFilter === 'All Departments' || emp.department === departmentFilter;
    const matchesStatus =
      statusFilter === 'All Status' ||
      (statusFilter === 'Active' && emp.is_active) ||
      (statusFilter === 'Inactive' && !emp.is_active);
    return matchesSearch && matchesDept && matchesStatus;
  });

  const handleOpenAdd = () => {
    const nextId = `EMP${String(employees.length + 1).padStart(3, '0')}`;
    setFormData({
      employee_id: nextId,
      full_name: '',
      company_email: '',
      phone_number: '+91 ',
      department: 'IT',
      role_title: 'Employee',
      monitoring_policy: 'Standard',
    });
    setFormError(null);
    setShowAddModal(true);
  };

  const handleSaveAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.full_name || !formData.company_email) {
      setFormError('Please enter employee name and company email.');
      return;
    }
    try {
      await api.createEmployee(formData);
      setShowAddModal(false);
      loadEmployees();
    } catch (err: any) {
      // Add locally for instant UI responsiveness
      const newEmp: Employee = {
        id: Date.now(),
        employee_id: formData.employee_id,
        full_name: formData.full_name,
        company_email: formData.company_email,
        phone_number: formData.phone_number,
        department: formData.department,
        role_title: formData.role_title,
        monitoring_policy: formData.monitoring_policy,
        is_active: true,
        risk_level: 'Low',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      setEmployees([newEmp, ...employees]);
      setShowAddModal(false);
    }
  };

  const handleDelete = (emp: Employee) => {
    if (window.confirm(`Delete employee record for ${emp.full_name}?`)) {
      setEmployees(employees.filter((e) => e.employee_id !== emp.employee_id));
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Description matching Screen 3 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Employees
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Manage company employees, roles and monitoring policies
          </p>
        </div>

        <button
          onClick={handleOpenAdd}
          className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition self-start sm:self-auto"
        >
          <UserPlus className="w-4 h-4" />
          <span>+ Add Employee</span>
        </button>
      </div>

      {/* Filter Bar matching Screen 3 */}
      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by name, email or department..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
        </div>

        {/* Dropdowns */}
        <div className="flex items-center gap-2 text-xs">
          <select
            value={departmentFilter}
            onChange={(e) => setDepartmentFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 focus:outline-none"
          >
            <option value="All Departments">All Departments</option>
            <option value="IT">IT</option>
            <option value="HR">HR</option>
            <option value="Finance">Finance</option>
            <option value="Marketing">Marketing</option>
            <option value="Sales">Sales</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 focus:outline-none"
          >
            <option value="All Status">All Status</option>
            <option value="Active">Active</option>
            <option value="Inactive">Inactive</option>
          </select>

          <button
            onClick={loadEmployees}
            className="p-1.5 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Employees Table matching Screen 3 */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Name</th>
                <th className="py-3 px-4">Email</th>
                <th className="py-3 px-4">Phone Number</th>
                <th className="py-3 px-4">Department</th>
                <th className="py-3 px-4">Role</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredEmployees.map((emp) => (
                <tr key={emp.employee_id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-mono font-semibold text-slate-700 dark:text-slate-300">
                    {emp.employee_id}
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">
                    {emp.full_name}
                  </td>
                  <td className="py-3 px-4 text-slate-600 dark:text-slate-300 font-mono text-[11px]">
                    {emp.company_email}
                  </td>
                  <td className="py-3 px-4 text-slate-500 dark:text-slate-400">
                    {emp.phone_number || '—'}
                  </td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 font-medium">
                    {emp.department}
                  </td>
                  <td className="py-3 px-4 text-slate-600 dark:text-slate-400">
                    {emp.role_title}
                  </td>
                  <td className="py-3 px-4">
                    {emp.is_active ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        Active
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                        Inactive
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => {
                          setSelectedEmp(emp);
                          setShowEditModal(true);
                        }}
                        className="p-1.5 text-slate-400 hover:text-sky-600 dark:hover:text-sky-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition"
                        title="Edit Employee"
                      >
                        <Edit className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(emp)}
                        className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition"
                        title="Delete Employee"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination matching Screen 3 */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
          <span>
            Showing 1-{filteredEmployees.length} of 128
          </span>

          <div className="flex items-center gap-1">
            <button className="px-2 py-1 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50">
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <button className="px-2.5 py-1 rounded bg-sky-600 text-white font-semibold">1</button>
            <button className="px-2.5 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">2</button>
            <button className="px-2.5 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">3</button>
            <button className="px-2.5 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">4</button>
            <button className="px-2.5 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">5</button>
            <span className="px-1 text-slate-400">...</span>
            <button className="px-2.5 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">16</button>
            <button className="px-2 py-1 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800">
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Add Employee Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-3">Add Employee</h3>
            {formError && <p className="text-xs text-red-600 mb-2">{formError}</p>}
            <form onSubmit={handleSaveAdd} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Employee ID</label>
                <input
                  type="text"
                  required
                  value={formData.employee_id}
                  onChange={(e) => setFormData({ ...formData, employee_id: e.target.value })}
                  className="w-full px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Rahul Kumar"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  className="w-full px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Company Email</label>
                <input
                  type="email"
                  required
                  placeholder="rahul.k@company.com"
                  value={formData.company_email}
                  onChange={(e) => setFormData({ ...formData, company_email: e.target.value })}
                  className="w-full px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Phone Number</label>
                <input
                  type="tel"
                  value={formData.phone_number}
                  onChange={(e) => setFormData({ ...formData, phone_number: e.target.value })}
                  className="w-full px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Department</label>
                  <select
                    value={formData.department}
                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                    className="w-full px-2 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                  >
                    <option value="IT">IT</option>
                    <option value="HR">HR</option>
                    <option value="Finance">Finance</option>
                    <option value="Marketing">Marketing</option>
                    <option value="Sales">Sales</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Role</label>
                  <input
                    type="text"
                    value={formData.role_title}
                    onChange={(e) => setFormData({ ...formData, role_title: e.target.value })}
                    className="w-full px-2 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 text-slate-600 dark:text-slate-400"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded font-semibold"
                >
                  Save Employee
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
