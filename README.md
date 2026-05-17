# CVE IDOR Proof of Concept (PoC) - Medkey Hospital Information System

## Vulnerability Overview
- **Target Software:** medkey-org/medkey (Hospital Information System & Electronic Health Records)
- **Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Improper Access Control
- **Common Weakness Enumeration:** CWE-639 (Access Control Bypass Through User-Controlled Key)
- **Affected Component:** `app\modules\medical\port\rest\controllers\PatientController`
- **Affected Method:** `actionGetPatientById($id)`
- **Impact:** High (Unauthorized Exfiltration of Protected Health Information - PHI)

## Vulnerability Description
An issue was discovered in the REST API endpoints of the Medkey open-source platform. The application handles patient record retrieval insecurely within `PatientController.php`. 

Specifically, the method `actionGetPatientById($id)` directly queries and exposes database records based entirely on the user-supplied `$id` parameter via HTTP GET requests, without verifying whether the authenticated session token belongs to the requested patient or an authorized medical professional. 

Because the underlying parent class `app\common\rest\ActiveController` also lacks global row-level or object-level access validation wrappers, any authenticated user can change the `id` query parameter (e.g., from `id=1` to `id=2`) to horizontally escalate privileges and exfiltrate sensitive medical history data, patient names, and active medical insurance policy details.

## Vulnerable Code Fragment
The following implementation demonstrates the lack of access controls and session correlation before data serialization:

```php
public function actionGetPatientById($id)
{
    return $this->asJson($this->patientService->getPatientById($id)->toArray([], ['policies.insurance']));
}

**## Proof of Concept (PoC) Simulation
**
Since the target environment relies on strict legacy dependencies that may face deprecation on modern container platforms, the core operational flaw can be simulated via an isolated lightweight handler environment (test_idor.php script included).
Exploit Replication Steps:

    Send an HTTP GET request to the vulnerable endpoint using a normal session parameter token:
    http://target-host/index.php/medical/patient/get-patient-by-id?id=1

    Modify the target resource identifier array range to target unauthorized nodes:
    http://target-host/index.php/medical/patient/get-patient-by-id?id=3

    Observe that the backend engine successfully outputs private identifiers (e.g., Patient Charts, Active Insurances) without throwing a 403 Forbidden Exception.

Remediation Standard (Fix)

To patch this vulnerability, explicit ownership validation must be executed prior to data fetching:
PHP

public function actionGetPatientById($id)
{
    if (\Yii::$app->user->id !== $id && !\Yii::$app->user->can('managePatients')) {
        throw new \yii\web\ForbiddenHttpException('Unauthorized access to patient charts.');
    }
    return $this->asJson($this->patientService->getPatientById($id)->toArray([], ['policies.insurance']));
}
