import {Component, OnInit} from "@angular/core";
import {Constants} from "@app/shared/constants/constants";
import {Router} from "@angular/router";
import {HttpClient} from "@angular/common/http";
import {AuthenticationService} from "@app/services/authentication.service";
import {HttpService} from "@app/shared/services/http.service";
import {AppDataService} from "@app/app-data.service";
import {TranslationService} from "@app/services/translation.service";
import {AppConfigService} from "@app/services/app-config.service";
import {BrowserCheckService} from "@app/shared/services/browser-check.service";

@Component({
  selector: "src-wizard",
  templateUrl: "./wizard.component.html"
})
export class WizardComponent implements OnInit {
  step: number = 1;
  emailRegexp = Constants.emailRegexp;
  password_score = 0;
  admin_check_password = "";
  recipientDuplicate = false;
  recipient_check_password = "";
  proxiedServer = false;
  tosAccept: boolean;
  license = "";
  completed = false;
  validation: {step2: boolean, step3: boolean, step4: boolean, step5: boolean, step6: boolean} = {step2: false, step3: false, step4: false, step5: false, step6: false};
  wizard = {
    "node_language": "en",
    "node_name": "",
    "admin_username": "",
    "admin_name": "",
    "admin_mail_address": "",
    "admin_password": "",
    "admin_escrow": true,
    "receiver_username": "",
    "receiver_name": "",
    "receiver_mail_address": "",
    "receiver_password": "",
    "skip_admin_account_creation": false,
    "skip_recipient_account_creation": false,
    "profile": "default",
    "enable_developers_exception_notification": false
  };

  config_profiles = [
    {
      name: "default",
      title: "Default",
      active: true
    }
  ];

  constructor(protected browserCheckService: BrowserCheckService, private translationService: TranslationService, private router: Router, private http: HttpClient, private authenticationService: AuthenticationService, private httpService: HttpService, protected appDataService: AppDataService, protected appConfigService: AppConfigService) {
  }

  ngOnInit() {
    this.verifyProxiedWizard();
    if (this.appDataService.public.node.wizard_done) {
      this.router.navigate(["/"]).then(_ => {
      });
      return;
    }
    this.loadLicense();
    this.wizard.node_language = this.translationService.language;

    if (this.appDataService.pageTitle === "") {
      this.appConfigService.setTitle();
    }
  }

  selectProfile(name: string) {
    const self = this;
    this.config_profiles.forEach(function (profile: { name: string,title: string, active: boolean }) {
      profile.active = profile.name === name;
      if (profile.active) {
        self.wizard.profile = profile.name;
      }
    });
  };

  complete() {

    if (this.completed) {
      return;
    }
    this.completed = true;

    const param = JSON.stringify(this.wizard);
    this.httpService.requestWizard(param).subscribe
    (
      {
        next: _ => {
          this.step += 1;
        }
      }
    );
  }

  verifyProxiedWizard(){
    if (!this.appDataService.public.node.wizard_done && window.location.host === 'localhost:4200') {
      console.log(window.navigator.userAgent);
      if(!window.navigator.userAgent.includes('Electron')){
        this.proxiedServer = true;
      }
    }
  }

  openLocalhost() {
    window.location.href = 'https://127.0.0.1:8443/';
  }

  validateDuplicateRecipient() {
    this.recipientDuplicate = this.wizard.receiver_username === this.wizard.admin_username;
    return this.recipientDuplicate;
  }

  goToAdminInterface() {
    const promise = () => {
      this.appConfigService.loadAdminRoute("/admin/home");
    };
    this.authenticationService.login(0, this.wizard.admin_username, this.wizard.admin_password, "", "", promise);
  }

  loadLicense() {
    this.http.get("license.txt", {responseType: "text"}).subscribe((data: string) => {
      this.license = data;
    });
  }

  onPasswordStrengthChange(score: number) {
    this.password_score = score;
  }

}