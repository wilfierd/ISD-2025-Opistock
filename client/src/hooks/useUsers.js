// client/src/hooks/useUsers.js
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import apiService from '../services/api';
import { toast } from 'react-toastify';

// Hook to fetch all users
export const useUsers = () => {
  return useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await apiService.users.getAll();
      return response.data.data;
    },
    retry: 1,
  });
};




// Hook to fetch a single user
export const useUser = (id) => {
  return useQuery({
    queryKey: ['users', id],
    queryFn: async () => {
      const response = await apiService.users.getById(id);
      return response.data.data;
    },
    retry: 1,
    enabled: !!id, // Only run the query if id is provided
  });
};

// Hook to create a new user
export const useCreateUser = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (userData) => apiService.users.create(userData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success('User added successfully');
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to add user');
    },
  });
};

// Hook to update an existing user
export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ id, data }) => apiService.users.update(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      queryClient.invalidateQueries({ queryKey: ['users', variables.id] });
      toast.success('User updated successfully');
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to update user');
    },
  });
};

// Hook to delete a user
export const useDeleteUser = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id) => apiService.users.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success('User deleted successfully');
    },
    onError: (err) => {
      toast.error(err.response?.data?.error || 'Failed to delete user');
    },
  });
};