// unified_data_ffi.cpp:124-137 (interfaces/cj/src, build commit a4882ad7,
// per case.json oh_source.build_provenance). Line 134 is the candidate:
// properties.tag flows unchecked into Utils::MallocCString, whose const
// std::string& parameter builds std::string(nullptr) -> strlen(NULL).
void FfiUDMFSetProperties(int64_t unifiedDataId, CUnifiedDataProperties properties)
{
    auto data = FFIData::GetData<CUnifiedData>(unifiedDataId);
    if (data == nullptr) {
        return;
    }
    auto prop = data->unifiedData_->GetProperties();
    AAFwk::WantParams wantP;
    SetDataParameters(properties.extras, wantP);
    prop->extras = wantP;
    prop->tag = Utils::MallocCString(properties.tag);
    prop->shareOptions = UDMF::ShareOptions(properties.shareOptions);
    data->unifiedData_->SetProperties(prop);
}
