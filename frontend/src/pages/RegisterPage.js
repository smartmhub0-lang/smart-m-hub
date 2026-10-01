import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiClient, formatApiError } from "@/App";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { CheckCircle, GraduationCap } from "lucide-react";
import { toast } from "sonner";

const initialForm = {
  name: "",
  email: "",
  address: "",
  phone: "",
  admin_name: "",
  admin_email: "",
  admin_phone: "",
  school_type: "",
  custom_school_type: "",
  school_classification: "",
  admin_password: "",
};

const RegisterPage = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState(initialForm);
  const [loading, setLoading] = useState(false);
  const [registrationSummary, setRegistrationSummary] = useState(null);
  const [paymentPhone, setPaymentPhone] = useState("");
  const [paymentLoading, setPaymentLoading] = useState(false);
  const [paymentSubmitted, setPaymentSubmitted] = useState(false);

  const updateField = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const validateForm = () => {
    const required = [
      ["name", "School Name"],
      ["email", "School Email"],
      ["address", "Physical Address"],
      ["phone", "School Phone Number"],
      ["admin_name", "Admin Name"],
      ["admin_email", "Admin Email"],
      ["admin_phone", "Admin Phone Number"],
      ["school_type", "Level of School"],
      ["school_classification", "Category of School"],
      ["admin_password", "School admin password"],
    ];

    for (const [field, label] of required) {
      if (!String(formData[field] || "").trim()) {
        toast.error(`${label} is required`);
        return false;
      }
    }
    if (formData.school_type === "other" && !formData.custom_school_type.trim()) {
      toast.error("Please specify the level of school");
      return false;
    }

    return true;
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!validateForm()) return;

    setLoading(true);

    try {
      const payload = {
        name: formData.name.trim(),
        email: formData.email.trim().toLowerCase(),
        address: formData.address.trim(),
        phone: formData.phone.trim(),
        school_type: formData.school_type === "other" ? formData.custom_school_type.trim() : formData.school_type,
        school_classification: formData.school_classification,
        operation_type: "day",
        admin_name: formData.admin_name.trim(),
        admin_email: formData.admin_email.trim().toLowerCase(),
        admin_phone: formData.admin_phone.trim(),
        admin_password: formData.admin_password,
        declarations_confirmed: true,
      };

      const response = await apiClient.post("/auth/register-school", payload);
      const data = response?.data || {};

      setRegistrationSummary({
        schoolId: data.school_id || "",
        schoolName: data.school_name || payload.name,
        schoolCode: data.school_code || "",
        approvalStatus: data.approval_status || "pending",
        paymentStatus: data.payment_status || "pending",
        activationFee: data.activation_invoice?.amount || 1000,
      });
      setFormData(initialForm);
      toast.success("School registration submitted successfully");
    } catch (error) {
      toast.error(formatApiError(error, "Registration failed"));
    } finally {
      setLoading(false);
    }
  };

  const handlePaymentSubmit = async (event) => {
    event.preventDefault();

    if (!registrationSummary?.schoolId || !registrationSummary?.schoolCode) {
      toast.error("School registration reference is missing. Please register again.");
      return;
    }

    if (!paymentPhone.trim()) {
      toast.error("Enter the phone number used to make payment");
      return;
    }

    setPaymentLoading(true);

    try {
      await apiClient.post("/auth/register-school/payment-phone", {
        school_id: registrationSummary.schoolId,
        school_code: registrationSummary.schoolCode,
        payment_phone: paymentPhone.trim(),
      });
      setPaymentSubmitted(true);
      toast.success("Payment phone submitted for verification");
    } catch (error) {
      toast.error(formatApiError(error, "Payment submission failed"));
    } finally {
      setPaymentLoading(false);
    }
  };

  if (registrationSummary) {
    return (
      <div className="min-h-screen bg-[#070B14] px-6 py-10 text-white">
        <div className="mx-auto max-w-3xl">
          <Button variant="outline" onClick={() => navigate("/")} className="mb-6">
            Back to Home
          </Button>

          <Card className="bg-[#101827] border-white/10">
            <CardHeader className="text-center space-y-4">
              <div className="mx-auto w-16 h-16 bg-emerald-500/15 border border-emerald-400/30 rounded-xl flex items-center justify-center">
                <CheckCircle className="w-9 h-9 text-emerald-300" />
              </div>
              <CardTitle className="text-3xl font-bold text-white">
                School registration submitted successfully.
              </CardTitle>
              <CardDescription className="text-slate-400">
                Complete the activation payment step so support can verify and approve your school.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-5">
                <p className="text-sm text-slate-300">School Code</p>
                <p className="mt-2 text-3xl font-bold tracking-wide text-emerald-300">
                  {registrationSummary.schoolCode}
                </p>
                <p className="mt-3 text-sm text-slate-300">
                  Copy this code. It will be used for your school login and for authorized school users.
                </p>
              </div>

              <div className="rounded-xl border border-white/10 bg-[#070B14] p-5">
                <h2 className="text-xl font-semibold text-white">Activation Payment</h2>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <div className="rounded-lg border border-white/10 bg-[#101827] p-4">
                    <p className="text-sm text-slate-400">Activation fee</p>
                    <p className="mt-1 text-2xl font-bold text-white">
                      KES {Number(registrationSummary.activationFee || 1000).toLocaleString()}
                    </p>
                    <p className="mt-2 text-sm text-slate-300">One-time charge during school registration.</p>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-[#101827] p-4">
                    <p className="text-sm text-slate-400">Payment number</p>
                    <p className="mt-1 text-2xl font-bold text-white">+254702641920</p>
                  </div>
                </div>

                <p className="mt-4 text-sm text-slate-300">
                  After registration, the school subscription is KES 2,000 per month, calculated from the registration date.
                </p>

                {paymentSubmitted ? (
                  <Alert className="mt-5 border-emerald-500/30 bg-emerald-500/10">
                    <CheckCircle className="h-4 w-4 text-emerald-300" />
                    <AlertDescription className="text-slate-200">
                      Your payment is being verified. The support team will approve your school soon.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <form onSubmit={handlePaymentSubmit} className="mt-5 space-y-4">
                    <div className="space-y-2">
                      <Label>Phone number used to make payment</Label>
                      <Input
                        value={paymentPhone}
                        onChange={(event) => setPaymentPhone(event.target.value)}
                        placeholder="+254..."
                        required
                      />
                    </div>
                    <Button type="submit" className="w-full" disabled={paymentLoading}>
                      {paymentLoading ? "Submitting..." : "Submit Payment Phone"}
                    </Button>
                  </form>
                )}
              </div>

              <div className="flex flex-col gap-3 sm:flex-row">
                <Button variant="outline" onClick={() => navigate("/login")} className="flex-1">
                  Access Portal
                </Button>
                <Button variant="outline" onClick={() => navigate("/")} className="flex-1">
                  Return Home
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#070B14] px-6 py-10 text-white">
      <div className="mx-auto max-w-3xl">
        <Button variant="outline" onClick={() => navigate("/")} className="mb-6">
          Back to Home
        </Button>

        <Card className="bg-[#101827] border-white/10">
          <CardHeader className="text-center space-y-4">
            <div className="mx-auto w-16 h-16 bg-emerald-500/15 border border-emerald-400/30 rounded-xl flex items-center justify-center">
              <GraduationCap className="w-9 h-9 text-emerald-300" />
            </div>
            <CardTitle className="text-3xl font-bold text-white">
              School Registration
            </CardTitle>
            <CardDescription className="text-slate-400">
              Submit your school details. Support will review and approve access after activation payment.
            </CardDescription>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>School Name</Label>
                  <Input value={formData.name} onChange={(e) => updateField("name", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>School Email</Label>
                  <Input type="email" value={formData.email} onChange={(e) => updateField("email", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>School Phone Number</Label>
                  <Input value={formData.phone} onChange={(e) => updateField("phone", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>Level of School</Label>
                  <Select value={formData.school_type} onValueChange={(value) => {
                    updateField("school_type", value);
                    updateField("custom_school_type", "");
                  }}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="primary">Primary</SelectItem>
                      <SelectItem value="junior_secondary">Junior Secondary</SelectItem>
                      <SelectItem value="senior_secondary">Senior Secondary</SelectItem>
                      <SelectItem value="secondary">Secondary</SelectItem>
                      <SelectItem value="college">College</SelectItem>
                      <SelectItem value="other">Other</SelectItem>
                    </SelectContent>
                  </Select>
                  {formData.school_type === "other" && (
                    <Input
                      placeholder="Type level of school"
                      value={formData.custom_school_type || ""}
                      onChange={(e) => updateField("custom_school_type", e.target.value)}
                      required
                    />
                  )}
                </div>

                <div className="space-y-2">
                  <Label>Category of School</Label>
                  <Select value={formData.school_classification} onValueChange={(value) => updateField("school_classification", value)}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select category" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="public">Public</SelectItem>
                      <SelectItem value="private">Private</SelectItem>
                      <SelectItem value="faith_based">Faith Based</SelectItem>
                      <SelectItem value="international">International</SelectItem>
                      <SelectItem value="special">Special School</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Admin Name</Label>
                  <Input value={formData.admin_name} onChange={(e) => updateField("admin_name", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>Admin Email</Label>
                  <Input type="email" value={formData.admin_email} onChange={(e) => updateField("admin_email", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>Admin Phone Number</Label>
                  <Input value={formData.admin_phone} onChange={(e) => updateField("admin_phone", e.target.value)} required />
                </div>

                <div className="space-y-2">
                  <Label>School Admin Password</Label>
                  <Input type="password" value={formData.admin_password} onChange={(e) => updateField("admin_password", e.target.value)} required />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Physical Address</Label>
                <Textarea value={formData.address} onChange={(e) => updateField("address", e.target.value)} required />
              </div>

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? "Submitting..." : "Submit School Registration"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default RegisterPage;
