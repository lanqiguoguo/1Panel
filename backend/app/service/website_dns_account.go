package service

import (
	"encoding/json"
	"fmt"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/dto/response"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

type WebsiteDnsAccountService struct {
}

type IWebsiteDnsAccountService interface {
	Page(search dto.PageInfo) (int64, []response.WebsiteDnsAccountDTO, error)
	Create(create request.WebsiteDnsAccountCreate) (request.WebsiteDnsAccountCreate, error)
	Update(update request.WebsiteDnsAccountUpdate) (request.WebsiteDnsAccountUpdate, error)
	Delete(id uint) error
}

func NewIWebsiteDnsAccountService() IWebsiteDnsAccountService {
	return &WebsiteDnsAccountService{}
}

// dnsSecretVars holds the DNS account authorization keys whose values are
// cloud-provider secrets and must be masked whenever an account is echoed
// back to the frontend. Identifier/config fields (accessKey, apiUser, region,
// email, id, authID, subAuthID, username, clientID) are not secrets and stay
// readable so the list and edit forms keep working.
var dnsSecretVars = map[string]struct{}{
	"apiSecret":     {},
	"authPassword":  {},
	"client_secret": {},
	"credential":    {},
	"password":      {},
	"refresh_token": {},
	"secret":        {},
	"secretID":      {},
	"secretKey":     {},
	"token":         {},
	"apiKey":        {},
}

// maskDnsAuthVars returns a copy of the authorization map with every secret
// value replaced by the same mask placeholder used for backup accounts
// (backupMaskValue). Key names are preserved so the edit form can still bind
// each field.
func maskDnsAuthVars(auth map[string]string) map[string]string {
	masked := make(map[string]string, len(auth))
	for key, value := range auth {
		if _, ok := dnsSecretVars[key]; ok {
			masked[key] = backupMaskValue
			continue
		}
		masked[key] = value
	}
	return masked
}

// mergeMaskedDnsAuthVars overlays the authorization map submitted from the
// edit form on top of the stored JSON, keeping the stored value for every
// secret field the form left at the mask placeholder (or empty). Non-secret
// fields and newly typed secrets take the submitted value. This gives the DNS
// account edit form the same "keep the stored secret" semantics as the backup
// account forms.
func mergeMaskedDnsAuthVars(storedVars string, reqVars map[string]string) (map[string]string, error) {
	storedMap := make(map[string]string)
	if err := json.Unmarshal([]byte(storedVars), &storedMap); err != nil {
		return nil, fmt.Errorf("unmarshal stored dns authorization failed, err: %v", err)
	}
	for key, value := range reqVars {
		if _, ok := dnsSecretVars[key]; ok && isMaskedCredential(value) {
			// Masked/empty secret: keep whatever is stored, skip the overwrite.
			continue
		}
		storedMap[key] = value
	}
	return storedMap, nil
}

func (w WebsiteDnsAccountService) Page(search dto.PageInfo) (int64, []response.WebsiteDnsAccountDTO, error) {
	total, accounts, err := websiteDnsRepo.Page(search.Page, search.PageSize, commonRepo.WithOrderBy("created_at desc"))
	var accountDTOs []response.WebsiteDnsAccountDTO
	for _, account := range accounts {
		auth := make(map[string]string)
		_ = json.Unmarshal([]byte(account.Authorization), &auth)
		accountDTOs = append(accountDTOs, response.WebsiteDnsAccountDTO{
			WebsiteDnsAccount: account,
			Authorization:     maskDnsAuthVars(auth),
		})
	}
	return total, accountDTOs, err
}

func (w WebsiteDnsAccountService) Create(create request.WebsiteDnsAccountCreate) (request.WebsiteDnsAccountCreate, error) {
	exist, _ := websiteDnsRepo.GetFirst(commonRepo.WithByName(create.Name))
	if exist != nil {
		return request.WebsiteDnsAccountCreate{}, buserr.New(constant.ErrNameIsExist)
	}

	authorization, err := json.Marshal(create.Authorization)
	if err != nil {
		return request.WebsiteDnsAccountCreate{}, err
	}

	if err := websiteDnsRepo.Create(model.WebsiteDnsAccount{
		Name:          create.Name,
		Type:          create.Type,
		Authorization: string(authorization),
	}); err != nil {
		return request.WebsiteDnsAccountCreate{}, err
	}

	return create, nil
}

func (w WebsiteDnsAccountService) Update(update request.WebsiteDnsAccountUpdate) (request.WebsiteDnsAccountUpdate, error) {
	old, err := websiteDnsRepo.GetFirst(commonRepo.WithByID(update.ID))
	if err != nil {
		return request.WebsiteDnsAccountUpdate{}, err
	}
	auth, err := mergeMaskedDnsAuthVars(old.Authorization, update.Authorization)
	if err != nil {
		return request.WebsiteDnsAccountUpdate{}, err
	}
	authorization, err := json.Marshal(auth)
	if err != nil {
		return request.WebsiteDnsAccountUpdate{}, err
	}
	exists, _ := websiteDnsRepo.List(commonRepo.WithByName(update.Name))
	for _, exist := range exists {
		if exist.ID != update.ID {
			return request.WebsiteDnsAccountUpdate{}, buserr.New(constant.ErrNameIsExist)
		}
	}
	if err := websiteDnsRepo.Save(model.WebsiteDnsAccount{
		BaseModel: model.BaseModel{
			ID: update.ID,
		},
		Name:          update.Name,
		Type:          update.Type,
		Authorization: string(authorization),
	}); err != nil {
		return request.WebsiteDnsAccountUpdate{}, err
	}

	return update, nil
}

func (w WebsiteDnsAccountService) Delete(id uint) error {
	if ssls, _ := websiteSSLRepo.List(websiteSSLRepo.WithByDnsAccountId(id)); len(ssls) > 0 {
		return buserr.New(constant.ErrAccountCannotDelete)
	}
	return websiteDnsRepo.DeleteBy(commonRepo.WithByID(id))
}
