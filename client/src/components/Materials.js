// client/src/components/Materials.js with packet number uniqueness validation
import React, { useState, useEffect, useMemo } from 'react';
import Navbar from './Navbar';
import { useLogout } from '../hooks/useAuth';
import { 
  useMaterials, 
  useCreateMaterial, 
  useUpdateMaterial, 
  useDeleteMaterial
} from '../hooks/useMaterials';
import { useCreateMaterialRequest } from '../hooks/useMaterialRequests';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

function Materials({ user }) {
  // State for search and selected material
  const [searchTerm, setSearchTerm] = useState('');
  const [searchField, setSearchField] = useState('partName'); // Default search field
  const [showFilterDropdown, setShowFilterDropdown] = useState(false); // State for dropdown visibility
  const [selectedMaterial, setSelectedMaterial] = useState(null);
  
  // Modal states
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [requestType, setRequestType] = useState('add');
  
  // QR code state
  const [showQrModal, setShowQrModal] = useState(false);
  
  // Form state for add/edit modal
  const [formData, setFormData] = useState({
    materialId: '',
    packetNo: '',
    partName: '',
    length: '',
    width: '',
    height: '',
    quantity: '',
    supplier: ''
  });

  // Validation errors state
  const [validationErrors, setValidationErrors] = useState({});

  // React Query hooks
  const { data: materials = [], isLoading, error } = useMaterials();
  const createMaterial = useCreateMaterial();
  const updateMaterial = useUpdateMaterial();
  const deleteMaterial = useDeleteMaterial();
  const createRequest = useCreateMaterialRequest();
  const logoutMutation = useLogout();

  // Check if user is admin
  const isAdmin = user.role === 'admin';
  const isManager = user.role === 'quản lý';
  const hasAdminAccess = isAdmin || isManager; // This check allows both roles to have the same access
  // Filter materials based on search term and search field
  const filteredMaterials = useMemo(() => {
    if (!searchTerm) return materials;
    
    return materials.filter(material => {
      switch(searchField) {
        case 'packetNo':
          return material.packetNo.toString().includes(searchTerm);
        case 'partName':
          return material.partName.toLowerCase().includes(searchTerm.toLowerCase());
        case 'supplier':
          return material.supplier.toLowerCase().includes(searchTerm.toLowerCase());
        case 'updatedBy':
          return material.updatedBy.toLowerCase().includes(searchTerm.toLowerCase());
        default:
          return material.partName.toLowerCase().includes(searchTerm.toLowerCase());
      }
    });
  }, [materials, searchTerm, searchField]);

  // Validation function to check for duplicate packet numbers
  const checkDuplicatePacketNo = () => {
    const packetNoToCheck = parseInt(formData.packetNo);
    
    // When editing, exclude the current material from the check
    if (formData.materialId) {
      return materials.some(material => 
        material.packetNo === packetNoToCheck && material.id !== formData.materialId
      );
    }
    
    // When adding a new material, check against all existing materials
    return materials.some(material => material.packetNo === packetNoToCheck);
  };

  // Form validation function
  const validateForm = () => {
    const errors = {};
    
    // Basic required field validation
    if (!formData.packetNo) {
      errors.packetNo = 'Packet No is required';
    }
    
    if (!formData.partName) {
      errors.partName = 'Part Name is required';
    }
    
    if (!formData.length) {
      errors.length = 'Length is required';
    }
    
    if (!formData.width) {
      errors.width = 'Width is required';
    }
    
    if (!formData.height) {
      errors.height = 'Height is required';
    }
    
    if (!formData.quantity) {
      errors.quantity = 'Quantity is required';
    }
    
    if (!formData.supplier) {
      errors.supplier = 'Supplier is required';
    }
    
    // Check for duplicate packet number
    const isDuplicate = checkDuplicatePacketNo();
    if (isDuplicate) {
      errors.packetNo = 'This packet number already exists. Packet numbers must be unique.';
    }
    
    setValidationErrors(errors);
    return Object.keys(errors).length === 0; // Return true if no errors
  };

  // Handle search input change
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  // Handle search field change
  const handleSearchFieldChange = (e) => {
    setSearchField(e.target.value);
    setSearchTerm(''); // Clear search term when changing fields
    setShowFilterDropdown(false); // Close dropdown after selection
  };
  
  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (showFilterDropdown && 
          !event.target.closest('.dropdown')) {
        setShowFilterDropdown(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showFilterDropdown]);

  // Handle material row click
  const handleMaterialClick = (material) => {
    setSelectedMaterial(material);
    setFormData({
      materialId: material.id,
      packetNo: material.packetNo,
      partName: material.partName,
      length: material.length,
      width: material.width,
      height: material.height,
      quantity: material.quantity,
      supplier: material.supplier
    });
    setValidationErrors({}); // Clear any previous validation errors
    setShowDetailsModal(true);
  };

  // Toggle add modal
  const handleAddClick = () => {
    setFormData({
      materialId: '',
      packetNo: '',
      partName: '',
      length: '',
      width: '',
      height: '',
      quantity: '',
      supplier: ''
    });
    setValidationErrors({}); // Clear any previous validation errors
    
    if (hasAdminAccess) {
      setShowAddModal(true);
    } else {
      setRequestType('add');
      setShowRequestModal(true);
    }
  };

  // Toggle edit modal (in detail view)
  const handleEditClick = () => {
    if (!hasAdminAccess) {
      setShowDetailsModal(false);
      setRequestType('edit');
      setShowRequestModal(true);
    }
  };

  // Toggle delete modal (in detail view)
  const handleDeleteClick = () => {
    if (hasAdminAccess) {
      setShowDeleteModal(true);
      setShowDetailsModal(false);
    } else {
      setShowDetailsModal(false);
      setRequestType('delete');
      setShowRequestModal(true);
    }
  };

  // Handle logout
  const handleLogout = () => {
    logoutMutation.mutate();
  };

  // Handle form input changes
  const handleInputChange = (e) => {
    const { id, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [id]: value
    }));
    
    // Clear the specific validation error when the user starts typing
    if (validationErrors[id]) {
      setValidationErrors(prev => ({
        ...prev,
        [id]: null
      }));
    }
  };

  // Handle form submission (admin only)
  const handleSaveClick = (isNewMaterial = false) => {
    // Run validation before proceeding
    if (!validateForm()) {
      // If validation fails, display error message and don't submit
      toast.error('Please correct the errors before saving');
      return;
    }
    
    const materialData = {
      packetNo: parseInt(formData.packetNo),
      partName: formData.partName,
      length: parseInt(formData.length),
      width: parseInt(formData.width),
      height: parseInt(formData.height),
      quantity: parseInt(formData.quantity),
      supplier: formData.supplier
    };

    if (isNewMaterial) {
      createMaterial.mutate(materialData, {
        onSuccess: () => {
          setShowAddModal(false);
          setValidationErrors({}); // Clear validation errors on success
        },
        onError: (error) => {
          // Handle server-side validation errors
          if (error.response?.data?.error) {
            toast.error(error.response.data.error);
            
            // If the error is about duplicate packet_no, update validation errors
            if (error.response.data.error.includes('packet number already exists')) {
              setValidationErrors(prev => ({
                ...prev,
                packetNo: 'This packet number already exists. Packet numbers must be unique.'
              }));
            }
          }
        }
      });
    } else {
      updateMaterial.mutate({ 
        id: formData.materialId, 
        data: materialData 
      }, {
        onSuccess: () => {
          setShowDetailsModal(false);
          setValidationErrors({}); // Clear validation errors on success
        },
        onError: (error) => {
          // Handle server-side validation errors
          if (error.response?.data?.error) {
            toast.error(error.response.data.error);
            
            // If the error is about duplicate packet_no, update validation errors
            if (error.response.data.error.includes('packet number already exists')) {
              setValidationErrors(prev => ({
                ...prev,
                packetNo: 'This packet number already exists. Packet numbers must be unique.'
              }));
            }
          }
        }
      });
    }
  };

  // Handle delete confirmation (admin only)
  const handleConfirmDelete = () => {
    if (selectedMaterial) {
      deleteMaterial.mutate(selectedMaterial.id, {
        onSuccess: () => {
          setShowDeleteModal(false);
        }
      });
    }
  };

  // Handle request submission (non-admin users)
  const handleSubmitRequest = () => {
    // Run validation before proceeding
    if (!validateForm()) {
      // If validation fails, display error message and don't submit
      toast.error('Please correct the errors before submitting the request');
      return;
    }
    
    const materialData = {
      packetNo: parseInt(formData.packetNo),
      partName: formData.partName,
      length: parseInt(formData.length),
      width: parseInt(formData.width),
      height: parseInt(formData.height),
      quantity: parseInt(formData.quantity),
      supplier: formData.supplier
    };
    
    let requestData = {};
    
    if (requestType === 'add') {
      requestData = {
        requestType: 'add',
        requestData: materialData
      };
    } else if (requestType === 'edit') {
      requestData = {
        requestType: 'edit',
        materialId: formData.materialId,
        requestData: materialData
      };
    } else if (requestType === 'delete') {
      requestData = {
        requestType: 'delete',
        materialId: selectedMaterial.id
      };
    }
    
    createRequest.mutate(requestData, {
      onSuccess: () => {
        setShowRequestModal(false);
        setValidationErrors({}); // Clear validation errors on success
      },
      onError: (error) => {
        // Handle server-side validation errors
        if (error.response?.data?.error) {
          toast.error(error.response.data.error);
          
          // If the error is about duplicate packet_no, update validation errors
          if (error.response.data.error.includes('packet number already exists')) {
            setValidationErrors(prev => ({
              ...prev,
              packetNo: 'This packet number already exists. Packet numbers must be unique.'
            }));
          }
        }
      }
    });
  };

  // Handle QR code generation
  const handlePrint = (id, e) => {
    e.stopPropagation(); // Prevent row click event
    
    const material = materials.find(m => m.id === id);
    if (!material) return;
    
    // Set up QR code modal data
    setSelectedMaterial(material);
    const materialUrl = `${window.location.origin}/material/${id}`;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(materialUrl)}`;
    
    setShowQrModal(true);
  };

  // Get placeholder text based on selected search field
  const getPlaceholderText = () => {
    switch(searchField) {
      case 'packetNo':
        return 'Tìm theo Packet No';
      case 'partName':
        return 'Tìm theo Part Name';
      case 'supplier':
        return 'Tìm theo Supplier';
      case 'updatedBy':
        return 'Tìm theo Updated By';
      default:
        return 'Tìm kiếm...';
    }
  };

  return (
    <div>
      <Navbar user={user} onLogout={handleLogout} />

      {/* Main Content */}
      <div className="container-fluid mt-4">
        {/* Search and Add Button */}
        <div className="row mb-3">
          <div className="col-md-8">
            <div className="d-flex">
              <div className="search-container flex-grow-1">
                <span className="search-icon"><i className="fas fa-search"></i></span>
                <input 
                  type="text" 
                  className="form-control" 
                  placeholder={getPlaceholderText()}
                  value={searchTerm}
                  onChange={handleSearch}
                />
              </div>
              
              {/* Filter Dropdown Button */}
              <div className="dropdown ms-2 position-relative">
                <button 
                  className="btn btn-light" 
                  type="button"
                  onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                >
                  <i className="fas fa-filter me-2"></i> Tìm theo
                </button>
                
                {showFilterDropdown && (
                  <div 
                    className="dropdown-menu shadow p-3 position-absolute" 
                    style={{ 
                      display: 'block', 
                      minWidth: '200px',
                      top: '100%',
                      left: 0,
                      zIndex: 1000
                    }}
                  >
                    <div className="form-check mb-2">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="searchFieldOptions"
                        id="packetNoOption"
                        value="packetNo"
                        checked={searchField === 'packetNo'}
                        onChange={handleSearchFieldChange}
                      />
                      <label className="form-check-label" htmlFor="packetNoOption">
                        Packet No
                      </label>
                    </div>
                    <div className="form-check mb-2">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="searchFieldOptions"
                        id="partNameOption"
                        value="partName"
                        checked={searchField === 'partName'}
                        onChange={handleSearchFieldChange}
                      />
                      <label className="form-check-label" htmlFor="partNameOption">
                        Part Name
                      </label>
                    </div>
                    <div className="form-check mb-2">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="searchFieldOptions"
                        id="supplierOption"
                        value="supplier"
                        checked={searchField === 'supplier'}
                        onChange={handleSearchFieldChange}
                      />
                      <label className="form-check-label" htmlFor="supplierOption">
                        Supplier
                      </label>
                    </div>
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="searchFieldOptions"
                        id="updatedByOption"
                        value="updatedBy"
                        checked={searchField === 'updatedBy'}
                        onChange={handleSearchFieldChange}
                      />
                      <label className="form-check-label" htmlFor="updatedByOption">
                        Updated by
                      </label>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="col-md-4 text-end">
            <button 
              className="btn btn-primary" 
              onClick={handleAddClick}
              disabled={hasAdminAccess ? createMaterial.isPending : createRequest.isPending}
            >
              {hasAdminAccess ? 'Add' : 'Request Add'}
            </button>
          </div>
        </div>

        {/* Materials List */}
        <h4>Danh sách nguyên vật liệu ({filteredMaterials.length})</h4>
        
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
                  <th width="5%"></th>
                  <th width="5%">Packet No</th>
                  <th width="20%">Part Name</th>
                  <th width="10%">Dài</th>
                  <th width="10%">Rộng</th>
                  <th width="10%">Cao</th>
                  <th width="5%">Quantity</th>
                  <th width="15%">Supplier</th>
                  <th width="10%">Updated by</th>
                  <th width="10%">Last Updated</th>
                  <th width="5%"></th>
                </tr>
              </thead>
              <tbody>
                {filteredMaterials.map(material => (
                  <tr 
                    key={material.id} 
                    onClick={() => handleMaterialClick(material)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div 
                        className={`status-dot ${selectedMaterial?.id === material.id ? 'active' : ''}`}
                      ></div>
                    </td>
                    <td>{material.packetNo}</td>
                    <td>{material.partName}</td>
                    <td>{material.length}</td>
                    <td>{material.width}</td>
                    <td>{material.height}</td>
                    <td>{material.quantity}</td>
                    <td>{material.supplier}</td>
                    <td>{material.updatedBy}</td>
                    <td>{material.lastUpdated}</td>
                    <td>
                      <button 
                        className="btn btn-sm" 
                        onClick={(e) => handlePrint(material.id, e)}
                        title="Generate QR Code"
                      >
                        <i className="fas fa-print"></i>
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredMaterials.length === 0 && (
                  <tr>
                    <td colSpan="11" className="text-center py-3">No materials found</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Material Details Modal */}
      {showDetailsModal && selectedMaterial && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Thông tin nguyên vật liệu</h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => {
                    setShowDetailsModal(false);
                    setSelectedMaterial(null);
                    setValidationErrors({});
                  }}
                ></button>
              </div>
              <div className="modal-body">
                {hasAdminAccess ? (
                  // Admin view - Edit form
                  <form id="materialForm">
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <label htmlFor="packetNo" className="form-label">Packet No</label>
                        <input 
                          type="number" 
                          className={`form-control ${validationErrors.packetNo ? 'is-invalid' : ''}`}
                          id="packetNo" 
                          value={formData.packetNo}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.packetNo && (
                          <div className="invalid-feedback">
                            {validationErrors.packetNo}
                          </div>
                        )}
                      </div>
                      <div className="col-md-6">
                        <label htmlFor="partName" className="form-label">Part Name</label>
                        <input 
                          type="text" 
                          className={`form-control ${validationErrors.partName ? 'is-invalid' : ''}`}
                          id="partName" 
                          value={formData.partName}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.partName && (
                          <div className="invalid-feedback">
                            {validationErrors.partName}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-4">
                        <label htmlFor="length" className="form-label">Dài</label>
                        <input 
                          type="number" 
                          className={`form-control ${validationErrors.length ? 'is-invalid' : ''}`}
                          id="length" 
                          value={formData.length}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.length && (
                          <div className="invalid-feedback">
                            {validationErrors.length}
                          </div>
                        )}
                      </div>
                      <div className="col-md-4">
                        <label htmlFor="width" className="form-label">Rộng</label>
                        <input 
                          type="number" 
                          className={`form-control ${validationErrors.width ? 'is-invalid' : ''}`}
                          id="width" 
                          value={formData.width}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.width && (
                          <div className="invalid-feedback">
                            {validationErrors.width}
                          </div>
                        )}
                      </div>
                      <div className="col-md-4">
                        <label htmlFor="height" className="form-label">Cao</label>
                        <input 
                          type="number" 
                          className={`form-control ${validationErrors.height ? 'is-invalid' : ''}`}
                          id="height" 
                          value={formData.height}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.height && (
                          <div className="invalid-feedback">
                            {validationErrors.height}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <label htmlFor="quantity" className="form-label">Quantity</label>
                        <input 
                          type="number" 
                          className={`form-control ${validationErrors.quantity ? 'is-invalid' : ''}`}
                          id="quantity" 
                          value={formData.quantity}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.quantity && (
                          <div className="invalid-feedback">
                            {validationErrors.quantity}
                          </div>
                        )}
                      </div>
                      <div className="col-md-6">
                        <label htmlFor="supplier" className="form-label">Supplier</label>
                        <input 
                          type="text" 
                          className={`form-control ${validationErrors.supplier ? 'is-invalid' : ''}`}
                          id="supplier" 
                          value={formData.supplier}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.supplier && (
                          <div className="invalid-feedback">
                            {validationErrors.supplier}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <p><strong>Updated By:</strong> {selectedMaterial.updatedBy}</p>
                      </div>
                      <div className="col-md-6">
                        <p><strong>Last Updated:</strong> {selectedMaterial.lastUpdated}</p>
                      </div>
                    </div>
                  </form>
                ) : (
                  // Regular user view - Read-only details
                  <div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <p><strong>Packet No:</strong> {selectedMaterial.packetNo}</p>
                      </div>
                      <div className="col-md-6">
                        <p><strong>Part Name:</strong> {selectedMaterial.partName}</p>
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-12">
                        <p><strong>Dimensions:</strong> {selectedMaterial.length} x {selectedMaterial.width} x {selectedMaterial.height}</p>
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <p><strong>Quantity:</strong> {selectedMaterial.quantity}</p>
                      </div>
                      <div className="col-md-6">
                        <p><strong>Supplier:</strong> {selectedMaterial.supplier}</p>
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <p><strong>Updated By:</strong> {selectedMaterial.updatedBy}</p>
                      </div>
                      <div className="col-md-6">
                        <p><strong>Last Updated:</strong> {selectedMaterial.lastUpdated}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => {
                    setShowDetailsModal(false);
                    setSelectedMaterial(null);
                    setValidationErrors({});
                  }}
                >
                  Close
                </button>
                
                {hasAdminAccess ? (
                  <>
                    <button 
                      type="button" 
                      className="btn btn-danger" 
                      onClick={handleDeleteClick}
                    >
                      Delete
                    </button>
                    <button 
                      type="button" 
                      className="btn btn-primary" 
                      onClick={() => handleSaveClick(false)}
                      disabled={updateMaterial.isPending}
                    >
                      {updateMaterial.isPending ? 'Saving...' : 'Save Changes'}
                    </button>
                  </>
                ) : (
                  <>
                    <button 
                      type="button" 
                      className="btn btn-warning" 
                      onClick={handleEditClick}
                    >
                      Request Edit
                    </button>
                    <button 
                      type="button" 
                      className="btn btn-danger" 
                      onClick={handleDeleteClick}
                    >
                      Request Delete
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Material Modal (Admin Only) */}
      {showAddModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Add New Material</h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => {
                    setShowAddModal(false);
                    setValidationErrors({});
                  }}
                ></button>
              </div>
              <div className="modal-body">
                <form id="addMaterialForm">
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <label htmlFor="packetNo" className="form-label">Packet No</label>
                      <input 
                        type="number" 
                        className={`form-control ${validationErrors.packetNo ? 'is-invalid' : ''}`}
                        id="packetNo" 
                        value={formData.packetNo}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.packetNo && (
                        <div className="invalid-feedback">
                          {validationErrors.packetNo}
                        </div>
                      )}
                    </div>
                    <div className="col-md-6">
                      <label htmlFor="partName" className="form-label">Part Name</label>
                      <input 
                        type="text" 
                        className={`form-control ${validationErrors.partName ? 'is-invalid' : ''}`}
                        id="partName" 
                        value={formData.partName}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.partName && (
                        <div className="invalid-feedback">
                          {validationErrors.partName}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="row mb-3">
                    <div className="col-md-4">
                      <label htmlFor="length" className="form-label">Dài</label>
                      <input 
                        type="number" 
                        className={`form-control ${validationErrors.length ? 'is-invalid' : ''}`}
                        id="length" 
                        value={formData.length}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.length && (
                        <div className="invalid-feedback">
                          {validationErrors.length}
                        </div>
                      )}
                    </div>
                    <div className="col-md-4">
                      <label htmlFor="width" className="form-label">Rộng</label>
                      <input 
                        type="number" 
                        className={`form-control ${validationErrors.width ? 'is-invalid' : ''}`}
                        id="width" 
                        value={formData.width}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.width && (
                        <div className="invalid-feedback">
                          {validationErrors.width}
                        </div>
                      )}
                    </div>
                    <div className="col-md-4">
                      <label htmlFor="height" className="form-label">Cao</label>
                      <input 
                        type="number" 
                        className={`form-control ${validationErrors.height ? 'is-invalid' : ''}`}
                        id="height" 
                        value={formData.height}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.height && (
                        <div className="invalid-feedback">
                          {validationErrors.height}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <label htmlFor="quantity" className="form-label">Quantity</label>
                      <input 
                        type="number" 
                        className={`form-control ${validationErrors.quantity ? 'is-invalid' : ''}`}
                        id="quantity" 
                        value={formData.quantity}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.quantity && (
                        <div className="invalid-feedback">
                          {validationErrors.quantity}
                        </div>
                      )}
                    </div>
                    <div className="col-md-6">
                      <label htmlFor="supplier" className="form-label">Supplier</label>
                      <input 
                        type="text" 
                        className={`form-control ${validationErrors.supplier ? 'is-invalid' : ''}`}
                        id="supplier" 
                        value={formData.supplier}
                        onChange={handleInputChange}
                        required 
                      />
                      {validationErrors.supplier && (
                        <div className="invalid-feedback">
                          {validationErrors.supplier}
                        </div>
                      )}
                    </div>
                  </div>
                </form>
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => {
                    setShowAddModal(false);
                    setValidationErrors({});
                  }}
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  className="btn btn-primary" 
                  onClick={() => handleSaveClick(true)}
                  disabled={createMaterial.isPending}
                >
                  {createMaterial.isPending ? 'Adding...' : 'Add Material'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal (Admin Only) */}
      {showDeleteModal && selectedMaterial && (
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
                <p>Are you sure you want to delete "{selectedMaterial.partName}"?</p>
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
                  disabled={deleteMaterial.isPending}
                >
                  {deleteMaterial.isPending ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Request Modal (Non-Admin Only) */}
      {showRequestModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  Request to {requestType.charAt(0).toUpperCase() + requestType.slice(1)} Material
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => {
                    setShowRequestModal(false);
                    setValidationErrors({});
                  }}
                ></button>
              </div>
              <div className="modal-body">
                {requestType === 'delete' ? (
                  <div>
                    <p>You are about to request deletion of the following material:</p>
                    <p><strong>Material:</strong> {selectedMaterial.partName} (ID: {selectedMaterial.id})</p>
                    <div className="alert alert-info">
                      <i className="fas fa-info-circle me-2"></i>
                      This request will be sent to an administrator for approval.
                    </div>
                  </div>
                ) : (
                  <>
                    <p>Fill in the details for your {requestType} request:</p>
                    <form id="materialRequestForm">
                      <div className="row mb-3">
                        <div className="col-md-6">
                          <label htmlFor="packetNo" className="form-label">Packet No</label>
                          <input 
                            type="number" 
                            className={`form-control ${validationErrors.packetNo ? 'is-invalid' : ''}`}
                            id="packetNo" 
                            value={formData.packetNo}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.packetNo && (
                            <div className="invalid-feedback">
                              {validationErrors.packetNo}
                            </div>
                          )}
                        </div>
                        <div className="col-md-6">
                          <label htmlFor="partName" className="form-label">Part Name</label>
                          <input 
                            type="text" 
                            className={`form-control ${validationErrors.partName ? 'is-invalid' : ''}`}
                            id="partName" 
                            value={formData.partName}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.partName && (
                            <div className="invalid-feedback">
                              {validationErrors.partName}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="row mb-3">
                        <div className="col-md-3">
                          <label htmlFor="length" className="form-label">Dài</label>
                          <input 
                            type="number" 
                            className={`form-control ${validationErrors.length ? 'is-invalid' : ''}`}
                            id="length" 
                            value={formData.length}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.length && (
                            <div className="invalid-feedback">
                              {validationErrors.length}
                            </div>
                          )}
                        </div>
                        <div className="col-md-3">
                          <label htmlFor="width" className="form-label">Rộng</label>
                          <input 
                            type="number" 
                            className={`form-control ${validationErrors.width ? 'is-invalid' : ''}`}
                            id="width" 
                            value={formData.width}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.width && (
                            <div className="invalid-feedback">
                              {validationErrors.width}
                            </div>
                          )}
                        </div>
                        <div className="col-md-3">
                          <label htmlFor="height" className="form-label">Cao</label>
                          <input 
                            type="number" 
                            className={`form-control ${validationErrors.height ? 'is-invalid' : ''}`}
                            id="height" 
                            value={formData.height}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.height && (
                            <div className="invalid-feedback">
                              {validationErrors.height}
                            </div>
                          )}
                        </div>
                        <div className="col-md-3">
                          <label htmlFor="quantity" className="form-label">Quantity</label>
                          <input 
                            type="number" 
                            className={`form-control ${validationErrors.quantity ? 'is-invalid' : ''}`}
                            id="quantity" 
                            value={formData.quantity}
                            onChange={handleInputChange}
                            required 
                          />
                          {validationErrors.quantity && (
                            <div className="invalid-feedback">
                              {validationErrors.quantity}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="mb-3">
                        <label htmlFor="supplier" className="form-label">Supplier</label>
                        <input 
                          type="text" 
                          className={`form-control ${validationErrors.supplier ? 'is-invalid' : ''}`}
                          id="supplier" 
                          value={formData.supplier}
                          onChange={handleInputChange}
                          required 
                        />
                        {validationErrors.supplier && (
                          <div className="invalid-feedback">
                            {validationErrors.supplier}
                          </div>
                        )}
                      </div>
                      <div className="alert alert-info">
                        <i className="fas fa-info-circle me-2"></i>
                        This request will be sent to an administrator for approval.
                      </div>
                    </form>
                  </>
                )}
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => {
                    setShowRequestModal(false);
                    setValidationErrors({});
                  }}
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  className="btn btn-primary" 
                  onClick={handleSubmitRequest}
                  disabled={createRequest.isPending}
                >
                  {createRequest.isPending ? 'Submitting...' : 'Submit Request'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* QR Code Modal */}
      {showQrModal && selectedMaterial && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Material QR Code: {selectedMaterial.partName}</h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => {
                    setShowQrModal(false);
                    setSelectedMaterial(null);
                  }}
                ></button>
              </div>
              <div className="modal-body text-center">
                <p>Scan this QR code to view material details:</p>
                <img 
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(`${window.location.origin}/material/${selectedMaterial.id}`)}`}
                  alt="QR Code"
                  className="img-fluid mb-3"
                  style={{ maxWidth: '200px' }}
                />
                <p className="small text-muted">
                  {`${window.location.origin}/material/${selectedMaterial.id}`}
                </p>
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => {
                    setShowQrModal(false);
                    setSelectedMaterial(null);
                  }}
                >
                  Close
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    // Print functionality
                    const printWindow = window.open('', '_blank');
                    printWindow.document.write(`
                      <html>
                      <head>
                        <title>Material QR Code: ${selectedMaterial.partName}</title>
                        <style>
                          body { font-family: Arial, sans-serif; margin: 20px; text-align: center; }
                          h2 { color: #0a4d8c; }
                          .material-info { margin: 20px 0; }
                          .qr-code { max-width: 300px; margin: 20px auto; }
                        </style>
                      </head>
                      <body>
                        <h2>Material QR Code</h2>
                        <div class="material-info">
                          <h3>${selectedMaterial.partName}</h3>
                          <p>Packet: ${selectedMaterial.packetNo} | Dimensions: ${selectedMaterial.length} x ${selectedMaterial.width} x ${selectedMaterial.height}</p>
                        </div>
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(`${window.location.origin}/material/${selectedMaterial.id}`)}" class="qr-code" />
                        <p>${window.location.origin}/material/${selectedMaterial.id}</p>
                      </body>
                      </html>
                    `);
                    printWindow.document.close();
                    setTimeout(() => {
                      printWindow.print();
                    }, 300);
                  }}
                >
                  Print
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Backdrop for modals */}
      {(showDetailsModal || showAddModal || showDeleteModal || showQrModal || showRequestModal) && (
        <div 
          className="modal-backdrop fade show"
          onClick={() => {
            setShowDetailsModal(false);
            setShowAddModal(false);
            setShowDeleteModal(false);
            setShowQrModal(false);
            setShowRequestModal(false);
            setSelectedMaterial(null);
            setValidationErrors({});
            
            // Also close filter dropdown if open
            setShowFilterDropdown(false);
          }}
        ></div>
      )}
    </div>
  );
}

export default Materials;