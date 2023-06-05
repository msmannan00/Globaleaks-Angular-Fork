import { Component } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { AppDataService } from 'app/src/app-data.service';
import { RecieverTipData } from 'app/src/models/reciever/RecieverTipData';
import { WBTipData } from 'app/src/models/whistleblower/WBTipData';
import { RecieverTipService } from 'app/src/services/recievertip.service';
import { DeleteConfirmationComponent } from 'app/src/shared/modals/delete-confirmation/delete-confirmation.component';
import { GrantAccessComponent } from 'app/src/shared/modals/grant-access/grant-access.component';
import { RevokeAccessComponent } from 'app/src/shared/modals/revoke-access/revoke-access.component';
import { PreferenceResolver } from 'app/src/shared/resolvers/preference.resolver';
import { RtipsResolver } from 'app/src/shared/resolvers/rtips.resolver';
import { HttpService } from 'app/src/shared/services/http.service';
import { UtilsService } from 'app/src/shared/services/utils.service';
import { Observable } from 'rxjs';
import { ChangeDetectorRef } from '@angular/core';
import { FieldUtilitiesService } from 'app/src/shared/services/field-utilities.service';


@Component({
  selector: 'src-tip',
  templateUrl: './tip.component.html',
  styleUrls: ['./tip.component.css']
})
export class TipComponent {
  tip_id: string | null;
  itemsPerPage: number = 5;
  currentCommentsPage: number = 1;
  currentMessagesPage: number = 1;
  answers: any = {};
  uploads: any = {};
  questionnaire: any={};  
  rows:any={}

  //
  tip: any={};
  contexts_by_id: any;
  Utils: any;
  submission_statuses: any;
  supportedViewTypes: string[];
  score: any;
  ctx: string;
  submission: {};
  fileupload_url: string;
  showEditLabelInput: boolean;
  // tip: any;



  set_reminder() { }
  tip_postpone() { }
  exportTip(tip: any) { }
 
  openGrantTipAccessModal() {
    alert('Alert from outside');

    this.utils.runUserOperation("get_users_names", {}, true).subscribe(
      {
        next: response => {
          const modalRef = this.modalService.open(GrantAccessComponent);
          modalRef.componentInstance.users_names = response;
          modalRef.componentInstance.confirmFun = (receiver_id: any) => {
            const args = {
              receiver: receiver_id
            };
            return this.utils.runRecipientOperation("grant", args, true);
          };
        },
        error: (error: any) => {
          alert(JSON.stringify(error));
        }
      }
    );
  }

  openRevokeTipAccessModal() {
    this.utils.runUserOperation("get_users_names", {}, true).subscribe(
      {
        next: response => {
          const modalRef = this.modalService.open(RevokeAccessComponent);
          modalRef.componentInstance.users_names = response;
          modalRef.componentInstance.confirmFun = (receiver_id: any) => {
            const args = {
              receiver: receiver_id
            };
            return this.utils.runRecipientOperation("revoke", args, true);
          };
        },
        error: (error: any) => {
          alert(JSON.stringify(error));
        }
      }
    );
  }
 
  reload(): void {
    this.utils.reloadCurrentRoute()
  }
  filterNotTriggeredField(parent: any, field: any, answers: any): void {
    let i;
    if (this.fieldUtilities.isFieldTriggered(parent, field, answers, this.tip.score)) {
      for (i = 0; i < field.children.length; i++) {
        this.filterNotTriggeredField(field, field.children[i], answers);
      }
    }
  }

  preprocessTipAnswers(tip:any) {
    let x, i, j, k, questionnaire, step;

    for (x=0; x<tip.questionnaires.length; x++) {
      this.questionnaire = tip.questionnaires[x];
      this.fieldUtilities.parseQuestionnaire(this.questionnaire, {});

      for (i=0; i<this.questionnaire.steps.length; i++) {
        step = this.questionnaire.steps[i];
        if (this.fieldUtilities.isFieldTriggered(null, step, this.questionnaire.answers, this.tip.score)) {
          for (j=0; j<step.children.length; j++) {
            this.filterNotTriggeredField(step, step.children[j], this.questionnaire.answers);
          }
        }
      }

      for (i=0; i<this.questionnaire.steps.length; i++) {
        step = this.questionnaire.steps[i];
        j = step.children.length;
        while (j--) {
          if (step.children[j]["template_id"] === "whistleblower_identity") {
            this.tip.whistleblower_identity_field = step.children[j];
            this.tip.whistleblower_identity_field.enabled = true;
            step.children.splice(j, 1);

            this.questionnaire = {
              steps: [{... this.tip.whistleblower_identity_field}]
            };

            this.tip.fields = this.questionnaire.steps[0].children;
            this.rows = this.fieldUtilities.splitRows(this.tip.fields);
            this.fieldUtilities.onAnswersUpdate(this);

            for (k=0; k<this.tip.whistleblower_identity_field.children.length; k++) {
              this.filterNotTriggeredField(this.tip.whistleblower_identity_field, this.tip.whistleblower_identity_field.children[k], this.tip.data.whistleblower_identity);
            }
          }
        }
      }
    }
  }
  ngOnInit() {
    this.loadTipDate();
  }

  loadTipDate(){
    this.tip_id = this.activatedRoute.snapshot.paramMap.get('tip_id');
    let requestObservable: Observable<any> = this.httpService.recieverTip({}, this.tip_id)
    requestObservable.subscribe(
      {
        next: (response: any) => {
          console.log(response)
          this.rtipService.initialize(response)
          this.tip = this.rtipService.tip;
          this.activatedRoute.queryParams.subscribe((params: { [x: string]: any; }) => {
            this.tip.tip_id = params['tip_id']
          });

          this.tip.context = this.appDataService.contexts_by_id[this.tip.context_id];
          this.tip.receivers_by_id = this.utilsService.array_to_map(this.tip.receivers);
          this.score = this.tip.score;
          this.ctx = "rtip";
          // this.exportTip = RTipExport;
          // this.downloadRFile = RTipDownloadRFile;
          // this.viewRFile = RTipViewRFile;
          this.showEditLabelInput = this.tip.label === "";
          this.preprocessTipAnswers(this.tip);
          this.tip.submissionStatusStr = this.utilsService.getSubmissionStatusText(this.tip.status, this.tip.substatus, this.appDataService.submission_statuses)
         
          this.submission = {};
         
        },
        error: (error: any) => {
        }
      }
    )
  }
 
  tipToggleStar() { }
  tipNotify(b: boolean) { }
  tipDelete() { }


  constructor(
    public utils: UtilsService,
    public preferencesService: PreferenceResolver,
    public modalService: NgbModal,
    private activatedRoute: ActivatedRoute,
    public httpService: HttpService,
    public appDataService: AppDataService,
    public utilsService: UtilsService,
    public rtipService :RecieverTipService,public fieldUtilities:FieldUtilitiesService, 
  ) {

  }
}
