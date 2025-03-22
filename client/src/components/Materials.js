// client/src/components/Materials.js
import React, { useState, useEffect, useMemo } from 'react';
import Navbar from './Navbar';
import { useLogout } from '../hooks/useAuth';
import { 
  useMaterials, 
  useCreateMaterial, 
  useUpdateMaterial, 
  useDeleteMaterial,
  useDeleteBatchMaterials
} from '../hooks/useMaterials';
// We'll use a different approach for QR codes

// QR Code Modal Component
const QRCodeModal = ({ id, material, onClose }) => {
  // Create URL for the material details page
  const materialUrl = `${window.location.origin}/material/${id}`;
  
  return (
    <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
      <div className="modal-dialog">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Material QR Code: {material.partName}</h5>
            <button 
              type="button" 
              className="btn-close" 
              onClick={onClose}
            ></button>
          </div>
          <div className="modal-body text-center">
            <p>Scan this QR code to view material details:</p>
            <img 
              src={`https://api.qrserver.com/v1/create-qr-code/?size=256x256&data=${encodeURIComponent(materialUrl)}`}
              alt="QR Code"
              width={256}
              height={256}
            />
            <p className="mt-3">
              <small className="text-muted">{materialUrl}</small>
            </p>
          </div>
          <div className="modal-footer">
            <button 
              type="button" 
              className="btn btn-secondary" 
              onClick={onClose}
            >
              Close
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                // Open the URL in a new tab
                window.open(materialUrl, '_blank');
              }}
            >
              Open Link
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

function Materials({ user }) {
  // State for selection and search
  const [selectedMaterials, setSelectedMaterials] = useState(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  
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
  
  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalMode, setModalMode] = useState('add'); // 'add' or 'edit'
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  
  // QR Code modal state
  const [showQrModal, setShowQrModal] = useState(false);
  const [selectedMaterialId, setSelectedMaterialId] = useState(null);

  // React Query hooks
  const { data: materials = [], isLoading, error } = useMaterials();
  const createMaterial = useCreateMaterial();
  const updateMaterial = useUpdateMaterial();
  const deleteMaterial = useDeleteMaterial();
  const deleteBatchMaterials = useDeleteBatchMaterials();
  const logoutMutation = useLogout();

  // Filter materials based on search term
  const filteredMaterials = useMemo(() => {
    return materials.filter(material => 
      material.partName.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [materials, searchTerm]);
  
  // Clear selections when data changes
  useEffect(() => {
    setSelectedMaterials(new Set());
  }, [materials]);

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  // Handle checkbox selection
  const handleCheckboxChange = (id) => {
    const newSelectedMaterials = new Set(selectedMaterials);
    if (newSelectedMaterials.has(id)) {
      newSelectedMaterials.delete(id);
    } else {
      newSelectedMaterials.add(id);
    }
    setSelectedMaterials(newSelectedMaterials);
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
    setModalMode('add');
    setShowModal(true);
  };

  // Toggle edit modal
  const handleEditClick = () => {
    if (selectedMaterials.size !== 1) return;
    
    const selectedId = Array.from(selectedMaterials)[0];
    const selectedMaterial = materials.find(m => m.id === selectedId);
    
    if (selectedMaterial) {
      setFormData({
        materialId: selectedMaterial.id,
        packetNo: selectedMaterial.packetNo,
        partName: selectedMaterial.partName,
        length: selectedMaterial.length,
        width: selectedMaterial.width,
        height: selectedMaterial.height,
        quantity: selectedMaterial.quantity,
        supplier: selectedMaterial.supplier
      });
      setModalMode('edit');
      setShowModal(true);
    }
  };

  // Toggle delete modal
  const handleDeleteClick = () => {
    if (selectedMaterials.size === 0) return;
    setShowDeleteModal(true);
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
  };

  // Handle form submission
  const handleSaveClick = () => {
    const materialData = {
      packetNo: parseInt(formData.packetNo),
      partName: formData.partName,
      length: parseInt(formData.length),
      width: parseInt(formData.width),
      height: parseInt(formData.height),
      quantity: parseInt(formData.quantity),
      supplier: formData.supplier
    };

    if (modalMode === 'add') {
      createMaterial.mutate(materialData, {
        onSuccess: () => {
          setShowModal(false);
        }
      });
    } else {
      updateMaterial.mutate({ 
        id: formData.materialId, 
        data: materialData 
      }, {
        onSuccess: () => {
          setShowModal(false);
        }
      });
    }
  };

  // Handle delete confirmation
  const handleConfirmDelete = () => {
    const selectedIds = Array.from(selectedMaterials);
    
    if (selectedIds.length === 1) {
      deleteMaterial.mutate(selectedIds[0], {
        onSuccess: () => {
          setShowDeleteModal(false);
        }
      });
    } else {
      deleteBatchMaterials.mutate(selectedIds, {
        onSuccess: () => {
          setShowDeleteModal(false);
        }
      });
    }
  };

  // Handle QR code generation
  const handlePrint = (id) => {
    const material = materials.find(m => m.id === id);
    if (!material) return;
    
    setSelectedMaterialId(id);
    setShowQrModal(true);
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
                placeholder="Tìm sản phẩm theo tên.."
                value={searchTerm}
                onChange={handleSearch}
              />
            </div>
          </div>
          <div className="col-md-6 text-end">
            <button 
              className="btn btn-primary btn-action" 
              onClick={handleAddClick}
              disabled={createMaterial.isPending}
            >
              {createMaterial.isPending ? 'Adding...' : 'Thêm vật phẩm'}
            </button>
            <button 
              className="btn btn-primary btn-action" 
              disabled={selectedMaterials.size !== 1 || updateMaterial.isPending}
              onClick={handleEditClick}
            >
              {updateMaterial.isPending ? 'Editing...' : 'Chỉnh sửa'}
            </button>
            <button 
              className="btn btn-primary btn-action" 
              disabled={selectedMaterials.size === 0 || deleteMaterial.isPending || deleteBatchMaterials.isPending}
              onClick={handleDeleteClick}
            >
              {(deleteMaterial.isPending || deleteBatchMaterials.isPending) ? 'Deleting...' : 'Xoá vật phẩm'}
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
                  <th width="5%">Số lượng</th>
                  <th width="15%">Nhà cung cấp</th>
                  <th width="10%">Người cập nhật</th>
                  <th width="10%">Cập nhật lần cuối</th>
                  <th width="5%"></th>
                </tr>
              </thead>
              <tbody>
                {filteredMaterials.map(material => (
                  <tr key={material.id}>
                    <td>
                      <input 
                        type="checkbox" 
                        className="form-check-input"
                        checked={selectedMaterials.has(material.id)}
                        onChange={() => handleCheckboxChange(material.id)}
                      />
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
                        onClick={() => handlePrint(material.id)}
                        title="Khởi tạo mã QR"
                      >
                        <i className="fas fa-print"></i>
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredMaterials.length === 0 && (
                  <tr>
                    <td colSpan="11" className="text-center py-3">Không tìm thấy nguyên vật liệu!</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add/Edit Modal */}
      {showModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  {modalMode === 'add' ? 'Add New Material' : 'Edit Material'}
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => setShowModal(false)}
                ></button>
              </div>
              <div className="modal-body">
                <form id="materialForm">
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <label htmlFor="packetNo" className="form-label">Packet No</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        id="packetNo" 
                        value={formData.packetNo}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                    <div className="col-md-6">
                      <label htmlFor="partName" className="form-label">Part Name</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        id="partName" 
                        value={formData.partName}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                  </div>
                  <div className="row mb-3">
                    <div className="col-md-3">
                      <label htmlFor="length" className="form-label">Dài</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        id="length" 
                        value={formData.length}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                    <div className="col-md-3">
                      <label htmlFor="width" className="form-label">Rộng</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        id="width" 
                        value={formData.width}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                    <div className="col-md-3">
                      <label htmlFor="height" className="form-label">Cao</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        id="height" 
                        value={formData.height}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                    <div className="col-md-3">
                      <label htmlFor="quantity" className="form-label">Quantity</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        id="quantity" 
                        value={formData.quantity}
                        onChange={handleInputChange}
                        required 
                      />
                    </div>
                  </div>
                  <div className="mb-3">
                    <label htmlFor="supplier" className="form-label">Supplier</label>
                    <input 
                      type="text" 
                      className="form-control" 
                      id="supplier" 
                      value={formData.supplier}
                      onChange={handleInputChange}
                      required 
                    />
                  </div>
                </form>
              </div>
              <div className="modal-footer">
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => setShowModal(false)}
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  className="btn btn-primary" 
                  onClick={handleSaveClick}
                  disabled={createMaterial.isPending || updateMaterial.isPending}
                >
                  {(createMaterial.isPending || updateMaterial.isPending) ? 'Saving...' : 'Lưu'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="modal fade show" style={{ display: 'block' }} tabIndex="-1">
          <div className="modal-dialog">
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
                Are you sure you want to delete the selected materials?
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
                  disabled={deleteMaterial.isPending || deleteBatchMaterials.isPending}
                >
                  {(deleteMaterial.isPending || deleteBatchMaterials.isPending) ? 'Deleting...' : 'Xoá vật phẩm'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* QR Code Modal */}
      {showQrModal && selectedMaterialId && (
        <QRCodeModal 
          id={selectedMaterialId} 
          material={materials.find(m => m.id === selectedMaterialId)}
          onClose={() => setShowQrModal(false)} 
        />
      )}
    </div>
  );
}

export default Materials;
