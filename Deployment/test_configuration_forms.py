import unittest
from pathlib import Path
from Deployment.configuration_forms import form
from Deployment.core_catalog import CoreCatalog
from Deployment.profile_registry import profiles, bind_profile, validate_profile_realization


class ConfigurationFormsTests(unittest.TestCase):
    def test_forms_reuse_profile_selection_and_native_realization(self):
        catalog = CoreCatalog(Path(__file__).resolve().parents[1])
        for profile in profiles():
            # The C++ form uses its real fixed init-demo provider; artifact
            # execution remains in installed/native integration verification.
            if profile['id']=='cpp-sctp-tls13': continue
            for role in profile['roles']:
                metadata = form(catalog,core=profile['core'],profile=profile['id'],role=role)
                self.assertEqual(metadata['template']['role'],role)
                validate_profile_realization(bind_profile(profile['core'],profile['id']),metadata['template'])
                self.assertTrue(metadata['secretFieldsWriteOnly'])
        with self.assertRaises(ValueError): form(catalog,core='go',profile='rust-quic',role='client')
