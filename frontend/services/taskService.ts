import { api, ApiResponse } from '@/lib/api';
import { Task, CreateTaskData, UpdateTaskData } from '../types/task';

// Task service functions
export const taskService = {
  /**
   * Get all tasks for the authenticated user with optional filtering and sorting
   * @param statusFilter Optional filter for task status ('all', 'completed', 'pending')
   * @param sortBy Optional sort field ('created_at', 'due_date', 'title')
   * @returns List of tasks
   */
  getTasks: async (statusFilter?: string, sortBy?: string): Promise<Task[]> => {
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.append('status', statusFilter);
      if (sortBy) params.append('sort', sortBy);

      const queryString = params.toString();
      const url = `/tasks${queryString ? '?' + queryString : ''}`;

      const response = await api.get<Task[]>(url);
      return response.data.data || [];
    } catch (error) {
      console.error('Error fetching tasks:', error);
      throw error;
    }
  },

  /**
   * Create a new task
   * @param taskData Task creation data
   * @returns Created task
   */
  createTask: async (taskData: CreateTaskData): Promise<Task> => {
    try {
      const response = await api.post<Task>('/api/tasks', taskData);
      if (!response.data.data) {
        throw new Error('Failed to create task: no data returned');
      }
      return response.data.data;
    } catch (error) {
      console.error('Error creating task:', error);
      throw error;
    }
  },

  /**
   * Get a specific task by ID
   * @param taskId ID of the task to retrieve
   * @returns Task object
   */
  getTaskById: async (taskId: number): Promise<Task> => {
    try {
      const response = await api.get<Task>(`/api/tasks/${taskId}`);
      if (!response.data.data) {
        throw new Error(`Failed to fetch task with ID ${taskId}: no data returned`);
      }
      return response.data.data;
    } catch (error) {
      console.error(`Error fetching task with ID ${taskId}:`, error);
      throw error;
    }
  },

  /**
   * Update a specific task
   * @param taskId ID of the task to update
   * @param taskData Task update data
   * @returns Updated task
   */
  updateTask: async (taskId: number, taskData: UpdateTaskData): Promise<Task> => {
    try {
      const response = await api.put<Task>(`/api/tasks/${taskId}`, taskData);
      if (!response.data.data) {
        throw new Error(`Failed to update task with ID ${taskId}: no data returned`);
      }
      return response.data.data;
    } catch (error) {
      console.error(`Error updating task with ID ${taskId}:`, error);
      throw error;
    }
  },

  /**
   * Toggle the completion status of a task
   * @param taskId ID of the task to toggle
   * @returns Updated task with new completion status
   */
  toggleTaskCompletion: async (taskId: number): Promise<Task> => {
    try {
      const response = await api.patch<Task>(`/api/tasks/${taskId}/complete`);
      if (!response.data.data) {
        throw new Error(`Failed to toggle completion for task with ID ${taskId}: no data returned`);
      }
      return response.data.data;
    } catch (error) {
      console.error(`Error toggling completion for task with ID ${taskId}:`, error);
      throw error;
    }
  },

  /**
   * Delete a specific task
   * @param taskId ID of the task to delete
   * @returns Success status
   */
  deleteTask: async (taskId: number): Promise<boolean> => {
    try {
      await api.delete(`/api/tasks/${taskId}`);
      return true;
    } catch (error) {
      console.error(`Error deleting task with ID ${taskId}:`, error);
      throw error;
    }
  }
};

export default taskService;