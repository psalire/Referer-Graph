
import ToggleElement from './StyledButton';

export default class URLFilterForm {
    private hostsFilterSuccessElem: ToggleElement;
    private hostsFilterBtn: HTMLElement|null;
    private hostsFilterText: HTMLElement|null;
    private hostsFilterDelimeter: HTMLElement|null;

    constructor() {
        this.hostsFilterBtn = document.getElementById('filter-input-btn');
        this.hostsFilterText = document.getElementById('filter-input-text');
        this.hostsFilterDelimeter = document.getElementById('filter-input-delimeter');
        this.hostsFilterText.value = 'ico,jpg,png,gif,css';
        this.hostsFilterDelimeter.value = ',';

        this.hostsFilterSuccessElem = new ToggleElement(document.getElementById('filter-input-success'));
        this.hostsFilterSuccessElem.addToggleValue('visible', 'visible', 'invisible')
                                   .addToggleValue('color', 'text-success', 'text-danger');
    }

    public getFilterText(): string {
        return this.hostsFilterText ? this.hostsFilterText.value : '';
    }
    public getFilterDelimeter(): string {
        return this.hostsFilterDelimeter ? this.hostsFilterDelimeter.value : '';
    }
    public getApplyButton(): HTMLElement|null {
        return this.hostsFilterBtn;
    }
    public displayFilterSuccessMessage(): void {
        if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
            return;
        }
        this.hostsFilterSuccessElem.setElem(document.getElementById('filter-input-success'))
                                   .toggleStyle('visible');
        setTimeout(() => {
            if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
                this.hostsFilterSuccessElem.toggleStyle('visible');
            }
        }, 3000);
    }
    public displayFilterErrorMessage(): void {
        if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
            return;
        }
        this.hostsFilterSuccessElem.setElem(document.getElementById('filter-input-success'))
                                   .toggleStyle('visible')
                                   .toggleStyle('color');
        this.hostsFilterSuccessElem.getElem().textContent = 'Error';
        setTimeout(() => {
            if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
                this.hostsFilterSuccessElem.toggleStyle('visible')
                                           .toggleStyle('color');
                this.hostsFilterSuccessElem.getElem().textContent = 'Success';
            }
        }, 3000);
    }
}
