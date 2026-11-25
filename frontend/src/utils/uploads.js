import { apiClient } from "@/App";

export async function uploadManagedFile(file, category) {
  if (!file) return "";

  const formData = new FormData();
  formData.append("file", file);
  formData.append("category", category);

  // Let Axios/browser add the multipart boundary. Setting this header by hand
  // omits the boundary and causes FastAPI to reject the form body.
  const response = await apiClient.post("/uploads", formData);

  return response?.data?.url || "";
}
