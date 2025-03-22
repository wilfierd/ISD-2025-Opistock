// client/src/components/Users.js
import React, { useState, useMemo } from 'react';
import Navbar from './Navbar';
import { useLogout } from '../hooks/useAuth';
import { toast } from 'react-toastify';
import '../styles/users.css';
import { 
  useUsers, 
  useUser,
  useCreateUser, 
  useUpdateUser, 
  useDeleteUser
} from '../hooks/useUsers';



function Users({ user }) {
  // State for user ID being viewed or edited
  const [selectedUserId, setSelectedUserId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Modal state
  const [showUserModal, setShowUserModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [modalMode, setModalMode] = useState('view'); // 'view', 'add', or 'edit'
  
  // Form state for add/edit modal
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    fullName: '',
    role: 'nhân viên',
    phone: ''
  });
  // Check if user is admin or managerhandleEditClick 
  const isAdmin = user.role === 'admin';
  const isManager = user.role === 'quản lý';
  const hasAdminAccess = isAdmin || isManager;
  // React Query hooks
  const { data: users = [], isLoading, error } = useUsers();
  const { data: selectedUser } = useUser(selectedUserId);
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();
  const logoutMutation = useLogout();

  // Filter users based on search term
  const filteredUsers = useMemo(() => {
    return users.filter(user => 
      user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.username.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [users, searchTerm]);

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  // Handle logout
  const handleLogout = () => {
    logoutMutation.mutate();
  };

  // Handle view user
  const handleViewUser = (id) => {
    setSelectedUserId(id);
    setModalMode('view');
    setShowUserModal(true);
  };

  // Handle add user click
  const handleAddClick = () => {
    setSelectedUserId(null);
    setFormData({
      username: '',
      password: '',
      fullName: '',
      role: 'nhân viên',
      phone: ''
    });
    setModalMode('add');
    setShowUserModal(true);
  };

  // Handle edit user click
  const handleEditClick = (id) => {
    const userToEdit = users.find(u => u.id === id);
    
    if (userToEdit) {
      // Check if manager is trying to edit an admin (not allowed)
      if (isManager && userToEdit.role === 'admin') {
        toast.error('Managers cannot edit admin users');
        return;
      }
      
      setSelectedUserId(id);
      setFormData({
        username: userToEdit.username,
        password: '', // Password field is empty for security
        fullName: userToEdit.full_name,
        role: userToEdit.role,
        phone: userToEdit.phone || ''
      });
      setModalMode('edit');
      setShowUserModal(true);
    }
  };

  // Handle delete user click
  const handleDeleteClick = (id) => {
    const userToDelete = users.find(u => u.id === id);
    
    // Check if manager is trying to delete an admin (not allowed)
    if (isManager && userToDelete.role === 'admin') {
      toast.error('Managers cannot delete admin users');
      return;
    }
    
    setSelectedUserId(id);
    setShowDeleteModal(true);
    setShowUserModal(false);
  };

  // Handle form input changes
  const handleInputChange = (e) => {
    const { id, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [id]: value
    }));
  };

  // Handle form submission
  const handleSaveClick = () => {
    const userData = {
      username: formData.username,
      fullName: formData.fullName,
      role: formData.role,
      phone: formData.phone
    };

    // Only include password if it's provided (for edit mode)
    if (formData.password) {
      userData.password = formData.password;
    }

    // If manager is trying to set someone as admin, prevent it
    if (isManager && formData.role === 'admin') {
      toast.error('Managers cannot assign admin role');
      return;
    }

    if (modalMode === 'add') {
      // Password is required for new users
      if (!formData.password) {
        toast.error('Password is required for new users');
        return;
      }
      
      createUser.mutate(userData, {
        onSuccess: () => {
          setShowUserModal(false);
          setSelectedUserId(null);
        }
      });
    } else {
      // If editing, check if manager is trying to edit an admin
      const userBeingEdited = users.find(u => u.id === selectedUserId);
      if (isManager && userBeingEdited.role === 'admin') {
        toast.error('Managers cannot modify admin users');
        return;
      }
      
      updateUser.mutate({ 
        id: selectedUserId, 
        data: userData 
      }, {
        onSuccess: () => {
          setShowUserModal(false);
          setSelectedUserId(null);
        }
      });
    }
  };

  // Handle delete confirmation
  const handleConfirmDelete = () => {
    if (selectedUserId) {
      // Final check to prevent deleting admin users by managers
      const userToDelete = users.find(u => u.id === selectedUserId);
      if (isManager && userToDelete.role === 'admin') {
        toast.error('Managers cannot delete admin users');
        setShowDeleteModal(false);
        return;
      }
      
      deleteUser.mutate(selectedUserId, {
        onSuccess: () => {
          setShowDeleteModal(false);
        }
      });
    }
  };

  // Close all modals and clear selection
  const closeAllModals = () => {
    setShowUserModal(false);
    setShowDeleteModal(false);
    setSelectedUserId(null);
  };

  return (
    <div>
      <Navbar user={user} onLogout={handleLogout} />

      {/* Main Content */}
      <div className="container-fluid mt-4">
        {/* Search and Action Buttons */}
        <div className="row mb-3">
          <div className="col-md-6">
            <div className="search-container">
              <span className="search-icon"><i className="fas fa-search"></i></span>
              <input 
                type="text" 
                className="form-control" 
                placeholder="Tìm nhân viên theo tên"
                value={searchTerm}
                onChange={handleSearch}
              />
            </div>
          </div>
          <div className="col-md-6 text-end">
            {user.role === 'admin' && (
              <button 
                className="btn btn-primary btn-action" 
                onClick={handleAddClick}
                disabled={createUser.isPending}
              >
                {createUser.isPending ? 'Adding...' : 'Add User'}
              </button>
            )}
          </div>
        </div>

        {/* Users List */}
        <h4>Số nhân viên ({filteredUsers.length})</h4>
        
        {isLoading ? (
          <div className="text-center my-5">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          </div>
        ) : error ? (
          <div className="alert alert-danger">{error.message}</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Tên đăng nhập</th>
                  <th>Họ và tên</th>
                  <th>Chức vụ</th>
                  <th>SĐT</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map(tableUser => (
                  <tr key={tableUser.id} onClick={() => handleViewUser(tableUser.id)} style={{ cursor: 'pointer' }}>
                    <td>{tableUser.id}</td>
                    <td>{tableUser.username}</td>
                    <td>{tableUser.full_name}</td>
                    <td>{tableUser.role}</td>
                    <td>{tableUser.phone || '-'}</td>
                    <td className="text-end">
                    {((hasAdminAccess && !(isManager && tableUser.role === 'admin')) || user.id === tableUser.id) && (
                        <button 
                          className="btn btn-sm" 
                          onClick={(e) => {
                            e.stopPropagation(); // Prevent row click
                            handleEditClick(tableUser.id);
                          }}
                        >
                          <i className="fas fa-edit"></i>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {filteredUsers.length === 0 && (
                  <tr>
                    <td colSpan="6" className="text-center py-3">No users found</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* User Modal (View/Edit/Add) */}
      {showUserModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  {modalMode === 'view' 
                    ? 'User Details' 
                    : modalMode === 'add' 
                      ? 'Add New User' 
                      : 'Edit User'}
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => {
                    setShowUserModal(false);
                    setSelectedUserId(null);
                  }}
                ></button>
              </div>
              <div className="modal-body">
                {modalMode === 'view' && selectedUser ? (
                  <div className="user-details-container">
                    <div className="user-detail-row">
                      <div className="user-detail-label">Username</div>
                      <div className="user-detail-value">{selectedUser.username}</div>
                    </div>
                    <div className="user-detail-row">
                      <div className="user-detail-label">Full Name</div>
                      <div className="user-detail-value">{selectedUser.full_name}</div>
                    </div>
                    <div className="user-detail-row">
                      <div className="user-detail-label">Role</div>
                      <div className="user-detail-value">{selectedUser.role}</div>
                    </div>
                    <div className="user-detail-row">
                      <div className="user-detail-label">Phone</div>
                      <div className="user-detail-value">{selectedUser.phone || '-'}</div>
                    </div>
                    <div className="user-detail-row">
                      <div className="user-detail-label">Created At</div>
                      <div className="user-detail-value">
                        {new Date(selectedUser.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ) : (
                  <form id="userForm">
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <label htmlFor="username" className="form-label">Username</label>
                        <input 
                          type="text" 
                          className="form-control" 
                          id="username" 
                          value={formData.username}
                          onChange={handleInputChange}
                          required 
                        />
                      </div>
                      <div className="col-md-6">
                        <label htmlFor="password" className="form-label">
                          Password {modalMode === 'edit' && '(Leave blank to keep current)'}
                        </label>
                        <input 
                          type="password" 
                          className="form-control" 
                          id="password" 
                          value={formData.password}
                          onChange={handleInputChange}
                          required={modalMode === 'add'} 
                        />
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <label htmlFor="fullName" className="form-label">Full Name</label>
                        <input 
                          type="text" 
                          className="form-control" 
                          id="fullName" 
                          value={formData.fullName}
                          onChange={handleInputChange}
                          required 
                        />
                      </div>
                      <div className="col-md-6">
                        <label htmlFor="role" className="form-label">Role</label>
                        <select 
                          className="form-select" 
                          id="role" 
                          value={formData.role}
                          onChange={handleInputChange}
                        >
                          <option value="nhân viên">Nhân viên</option>
                          <option value="quản lý">Quản lý</option>
                          {isAdmin && <option value="admin">Admin</option>}
                        </select>
                      </div>
                    </div>
                    <div className="mb-3">
                      <label htmlFor="phone" className="form-label">Phone Number</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        id="phone" 
                        value={formData.phone}
                        onChange={handleInputChange}
                      />
                    </div>
                  </form>
                )}
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => {
                    setShowUserModal(false);
                    setSelectedUserId(null);
                  }}
                >
                  {modalMode === 'view' ? 'Close' : 'Cancel'}
                </button>
                
                {modalMode !== 'view' && (
                  <button 
                    type="button" 
                    className="btn btn-primary" 
                    onClick={handleSaveClick}
                    disabled={createUser.isPending || updateUser.isPending}
                  >
                    {(createUser.isPending || updateUser.isPending) ? 'Saving...' : 'Save'}
                  </button>
                )}
                
                {modalMode === 'view' && user.role === 'admin' && selectedUser && selectedUser.id !== user.id && (
                  <>
                    {(isAdmin || (isManager && selectedUser && selectedUser.role !== 'admin')) && (
                      <button 
                        type="button" 
                        className="btn btn-primary" 
                        onClick={() => {
                          handleEditClick(selectedUser.id);
                        }}
                      >
                        Edit
                      </button>
                    )}
                    {(isAdmin || (isManager && selectedUser && selectedUser.role !== 'admin')) && selectedUser && selectedUser.id !== user.id && (
                      <button 
                        type="button" 
                        className="btn btn-danger" 
                        onClick={() => {
                          setShowUserModal(false);
                          handleDeleteClick(selectedUser.id);
                        }}
                      >
                        Delete
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Confirm Delete</h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => setShowDeleteModal(false)}
                ></button>
              </div>
              <div className="modal-body">
                Are you sure you want to delete this user?
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => setShowDeleteModal(false)}
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  className="btn btn-danger" 
                  onClick={handleConfirmDelete}
                  disabled={deleteUser.isPending}
                >
                  {deleteUser.isPending ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Backdrop for modals */}
      {(showUserModal || showDeleteModal) && (
        <div 
          className="modal-backdrop fade show" 
          onClick={closeAllModals}
        ></div>
      )}
    </div>
  );
}

export default Users;