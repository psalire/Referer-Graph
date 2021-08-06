
import StyledButton from './StyledButton';

export default class LiveUpdateButton extends StyledButton {
    private isLiveUpdateOn: boolean=true;

    constructor() {
        super('', 'btn-success', true);
        this.setText(this.createIsLiveButtonText(), true);
        this.addToggleValue('color', 'btn-success', 'btn-secondary');
        this.getButton().addEventListener('click', ()=>{
            this.isLiveUpdateOn = !this.isLiveUpdateOn;
            this.toggleStyle('color');
            this.setText(this.createIsLiveButtonText(), true);
        });
    }

    public getIsLiveUpdateOn(): boolean {
        return this.isLiveUpdateOn;
    }
    private createIsLiveButtonText(): string {
        return `Live Update: <span class="fw-bold">${this.getIsLiveUpdateOn()?'ON':'OFF'}</span>`;
    }
}
